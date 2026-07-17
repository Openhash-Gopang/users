/**
 * pdv-history-client.js — PDV_REQUEST / PDV_HISTORY_REQUEST 태그 클라이언트 실행기
 * SSOT: gopang 저장소 루트의 이 파일. gopang-wallet.js와 동일한 배포 패턴으로
 * 각 K-서비스 저장소(school/stock/tax/health/... )에 그대로 복사해 사용한다.
 *
 * ■ 왜 필요한가 (2026-07-04, PDV_HISTORY_REQUEST 사고실험에서 발견)
 * K-Public_common P10/P11, 각 K-서비스 SP는 [PDV_REQUEST:...] / [PDV_HISTORY_
 * REQUEST:...] 태그를 발화하도록 지시받지만, 그 태그를 실제로 가로채 /pdv/query를
 * 호출하는 클라이언트 코드가 어느 저장소에도 없었다. 이 파일이 그 실행 계층이다.
 *
 * ■ 흐름 (hondi.net/consent.html의 실제 구현에 맞춘 전체 페이지 리다이렉트 방식 —
 *   팝업/postMessage가 아니다)
 *   1. LLM 응답에서 태그 감지
 *   2. localStorage에 저장된 동의(scope별)가 있으면 그걸로 바로 /pdv/query
 *   3. 없거나 만료됐으면 /pdv/query → 202 CONSENT_REQUIRED → consent_url로
 *      현재 페이지를 통째로 이동(return_to=현재 URL을 서버가 이미 담아 보냄)
 *   4. consent.html이 승인 처리 후 원래 페이지로 ?consent_token=...&req=...를
 *      붙여 리다이렉트 → 페이지 로드 시 checkPdvConsentReturn()으로 회수·저장
 *
 * ■ 사용법 (통합 예시는 gopang 저장소의 tax/webapp.html, school/js/app.js 참조)
 *   - 페이지 로드 시 1회: const back = checkPdvConsentReturn(); back이 있으면
 *     back.granted/denied로 분기해 원래 하려던 응답을 이어간다.
 *   - AI 응답을 받을 때마다: const r = await interceptPdvTags(aiText, {svc, ipv6});
 *     r.redirecting이면 페이지가 이미 이동 중이므로 그대로 둔다.
 *     r.results가 있으면 각 결과(summary/error)를 다음 LLM 호출의 컨텍스트로 주입한다.
 *
 * ■ 인증 레벨 수정 (2026-07-04b, 배포 직후 사고실험에서 발견)
 * 최초 버전은 호출부가 만든 `{exp, level:'L1'}` 객체를 auth_token으로 그대로
 * 서버에 보냈다 — 서버는 이 값을 서명 검증 없이 그대로 믿었으므로, 누구든
 * level:'L3'라고 우기면 통과되는 구멍이었다(현재는 모든 scope가 L1 이하만
 * 요구해 당장은 무해했지만, L2/L3 scope가 하나라도 추가되면 12개 서비스
 * 전체가 동시에 뚫리는 구조였다). worker.js가 이미 gopang_token 쿠키를
 * HMAC-SHA256으로 서명·검증하는 buildToken/parseToken을 갖고 있었으므로
 * (handleVerify/handleRefresh에서 이미 사용 중), /pdv/query도 같은 쿠키를
 * credentials:'include'로 전달해 서버가 직접 레벨을 검증하도록 바꿨다.
 * 클라이언트는 더 이상 자신의 인증 레벨을 자칭하지 않는다 — authToken
 * 파라미터는 호출부 호환을 위해 계속 받아들이지만 무시하고 전송하지 않는다.
 */

const PDV_PROXY = 'https://hondi-proxy.tensor-city.workers.dev';
const PDV_TAG_RE = /\[PDV(?:_HISTORY)?_REQUEST:\s*([^\]]+)\]/g;

function _pdvConsentKey(scope) { return `pdv_consent:${scope}`; }

function _loadPdvConsent(scope) {
  try { return JSON.parse(localStorage.getItem(_pdvConsentKey(scope)) || 'null'); }
  catch { return null; }
}

function _savePdvConsent(scope, requestId, consentToken) {
  try {
    localStorage.setItem(_pdvConsentKey(scope), JSON.stringify({
      request_id: requestId, consent_token: consentToken, saved_at: Date.now(),
    }));
  } catch (e) { console.warn('[PDV] 동의 저장 실패:', e.message); }
}

function _parseTagParams(paramStr) {
  const params = {};
  paramStr.split(',').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    params[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  });
  return params;
}

function _periodToRange(periodStr) {
  const days = parseInt(periodStr) || 180; // 기본 180일 — K-Public_common P11 기본값과 동일
  const end = new Date();
  const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
  return { start: start.toISOString().slice(0, 10), end: end.toISOString().slice(0, 10) };
}

/**
 * 페이지 로드 시 최초 1회 호출한다. consent.html에서 방금 돌아온 것인지 확인하고,
 * 그렇다면 URL의 consent_token/req를 저장한 뒤 URL을 정리한다(새로고침·뒤로가기 시
 * 중복 처리 방지).
 * @returns {null|{scope:string, granted?:boolean, denied?:boolean, resumeContext?:*}}
 */
function checkPdvConsentReturn() {
  const url = new URL(location.href);
  const consentToken  = url.searchParams.get('consent_token');
  const consentDenied = url.searchParams.get('consent_denied');
  const req           = url.searchParams.get('req');
  if (!req || (!consentToken && !consentDenied)) return null;

  let pending = null;
  try { pending = JSON.parse(sessionStorage.getItem('pdv_pending_request') || 'null'); } catch {}

  url.searchParams.delete('consent_token');
  url.searchParams.delete('consent_denied');
  url.searchParams.delete('req');
  history.replaceState({}, '', url.toString());

  if (!pending || pending.request_id !== req) return null;
  sessionStorage.removeItem('pdv_pending_request');

  if (consentDenied) return { scope: pending.scope, denied: true, resumeContext: pending.resumeContext };

  _savePdvConsent(pending.scope, req, consentToken);
  return { scope: pending.scope, granted: true, resumeContext: pending.resumeContext };
}

/**
 * 단일 scope에 대해 PDV 조회를 시도한다. 동의가 필요하면 현재 페이지를
 * consent.html로 리다이렉트하고(location.href 대입) {redirecting:true}를 반환한다
 * — 이 시점 이후 현재 페이지의 JS 실행은 곧 중단되므로 호출부는 후속 로직을
 * 최소화해야 한다.
 */
async function queryPdvScope({ svc, ipv6, scope, period, reason, resumeContext, sessionToken }) {
  const stored = _loadPdvConsent(scope);
  const body = {
    query: {
      svc, ipv6, scope: [scope], period: _periodToRange(period),
      purpose: reason || '',
      ...(stored ? { consent_token: stored.consent_token, request_id: stored.request_id } : {}),
    },
  };

  const headers = { 'Content-Type': 'application/json' };
  // 2026-07-04b: sessionToken이 있으면(handleIssue가 내려준 실제 서명된
  // 토큰) Bearer로 실어 보낸다 — 서버가 이걸로 진짜 인증 레벨을 검증한다.
  // 없으면 그냥 보내지 않는다: 서버는 검증 불가 요청을 자동으로 L1로
  // 취급하므로(handlePdvQuery 2026-07-04b 참고) 오늘 등록된 모든 scope는
  // sessionToken 없이도 기존과 동일하게 동작한다.
  if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;

  let res, data;
  try {
    res = await fetch(`${PDV_PROXY}/pdv/query`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    data = await res.json().catch(() => null);
  } catch (e) {
    return { ok: false, error: 'NETWORK_ERROR: ' + e.message };
  }

  if (res.status === 202 && data?.status === 'CONSENT_REQUIRED') {
    // 저장돼 있던 동의가 있었는데도 CONSENT_REQUIRED가 왔다면(90일 만료 등) 폐기
    if (stored) localStorage.removeItem(_pdvConsentKey(scope));
    sessionStorage.setItem('pdv_pending_request', JSON.stringify({
      scope, request_id: data.consent.request_id, resumeContext: resumeContext || null,
    }));
    location.href = data.consent.consent_url;
    return { redirecting: true };
  }

  if (!data?.ok) {
    return { ok: false, error: data?.detail || data?.error || 'PDV_QUERY_FAILED' };
  }
  return { ok: true, summary: data.pdv_summary?.[scope] || null };
}

/**
 * LLM 응답 텍스트에서 [PDV_REQUEST:...] / [PDV_HISTORY_REQUEST:...] 태그를 찾아
 * 순서대로 실행한다. 태그가 없으면 null. 리다이렉트가 발생하면 {redirecting:true}만
 * 반환한다(그 시점에서 사실상 페이지 이동이 시작됨).
 */
async function interceptPdvTags(responseText, { svc, ipv6, resumeContext, sessionToken, authToken } = {}) {
  // authToken 파라미터는 구버전 호출부와의 하위 호환을 위해 계속 받되
  // 사용하지 않는다(2026-07-04b) — 대신 sessionToken을 쓴다.
  const matches = [...responseText.matchAll(PDV_TAG_RE)];
  if (!matches.length) return null;

  const results = [];
  for (const m of matches) {
    const params = _parseTagParams(m[1]);
    if (!params.scope) continue;
    const r = await queryPdvScope({
      svc, ipv6, scope: params.scope, period: params.period,
      reason: params.reason, resumeContext, sessionToken,
    });
    if (r.redirecting) return { redirecting: true };
    results.push({ scope: params.scope, ...r });
  }
  return { results };
}

// 각 서비스 저장소는 대부분 모듈이 아닌 일반 <script> 태그로 앱을 구성하므로
// (예: gopang-wallet.js가 window.gopangWallet으로 노출되는 것과 동일한 패턴),
// ES 모듈 export 대신 전역 객체로 노출한다. 모듈 환경에서 쓰고 싶다면
// `const { interceptPdvTags, checkPdvConsentReturn, queryPdvScope } = window.PdvHistoryClient;`
// 로 구조분해하면 된다.
window.PdvHistoryClient = { interceptPdvTags, checkPdvConsentReturn, queryPdvScope };
