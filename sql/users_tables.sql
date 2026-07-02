-- ================================================================
-- users_tables.sql
-- users.hondi.net 전용 신규 테이블 + RPC + Worker 엔드포인트
-- 기존 테이블(users, user_profiles, seller_ratings,
--             location_log, inventory 등) 수정 없음
-- 작성: AI City Inc. 팀 주피터 / 2026-06
-- ================================================================

-- ================================================================
-- SECTION 1: 신규 테이블 3개
-- ================================================================

-- ── 1-A. user_nicknames ─────────────────────────────────────────
-- user_profiles에 닉네임 컬럼이 없으므로 별도 테이블로 관리
-- SP-USERS-v2_0 STEP 05-C1 에서 참조
CREATE TABLE IF NOT EXISTS user_nicknames (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  guid          text        NOT NULL REFERENCES users(guid) ON DELETE CASCADE,
  nickname      text        NOT NULL,
  nickname_hash text        NOT NULL,           -- SHA-256(nickname), 검색 키
  status        text        NOT NULL DEFAULT 'active',
  -- 'active' | 'transitioning' | 'expired'
  -- transitioning: 닉네임 변경 중 (30일 이후 경매)
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_nickname_hash UNIQUE (nickname_hash),
  CONSTRAINT uq_guid_active   UNIQUE (guid, status)
  -- 한 사용자는 active 닉네임 1개만 허용
);

CREATE INDEX IF NOT EXISTS idx_user_nicknames_guid
  ON user_nicknames(guid);
CREATE INDEX IF NOT EXISTS idx_user_nicknames_hash
  ON user_nicknames(nickname_hash);
CREATE INDEX IF NOT EXISTS idx_user_nicknames_status
  ON user_nicknames(status);

COMMENT ON TABLE  user_nicknames               IS 'GAS 닉네임 (DHT Key 기반 검색용)';
COMMENT ON COLUMN user_nicknames.nickname_hash IS 'SHA-256(nickname) hex — 검색 기본 키';
COMMENT ON COLUMN user_nicknames.status        IS 'active | transitioning | expired';


-- ── 1-B. user_trust_levels ──────────────────────────────────────
-- GAS v1.6 신뢰 등급 (L0~L3)
-- user_profiles에 trust 컬럼이 없으므로 별도 테이블
CREATE TABLE IF NOT EXISTS user_trust_levels (
  guid        text        NOT NULL PRIMARY KEY REFERENCES users(guid) ON DELETE CASCADE,
  trust_level text        NOT NULL DEFAULT 'L0',
  -- 'L0' | 'L1' | 'L2' | 'L3'
  verified_at timestamptz,
  verifier    text                              -- 검증 기관 또는 방법
);

CREATE INDEX IF NOT EXISTS idx_user_trust_levels_level
  ON user_trust_levels(trust_level);

COMMENT ON TABLE  user_trust_levels             IS 'GAS v1.6 신뢰 등급 L0~L3';
COMMENT ON COLUMN user_trust_levels.trust_level IS 'L0=익명 L1=인증 L2=스테이킹 L3=검증됨';
COMMENT ON COLUMN user_trust_levels.verifier    IS '검증 기관(예: gopang-webauthn, kyc-provider)';


-- ── 1-C. user_gdc_settings ──────────────────────────────────────
-- GDC 결제 수락 여부 (K-Market 거래 필터에서 사용)
-- user_profiles.extra jsonb에 넣을 수도 있으나,
-- 인덱스 검색과 명시적 스키마를 위해 별도 테이블로 분리
CREATE TABLE IF NOT EXISTS user_gdc_settings (
  guid         text        NOT NULL PRIMARY KEY REFERENCES users(guid) ON DELETE CASCADE,
  gdc_accepted boolean     NOT NULL DEFAULT false,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_gdc_settings_accepted
  ON user_gdc_settings(gdc_accepted) WHERE gdc_accepted = true;

COMMENT ON TABLE  user_gdc_settings              IS 'GDC 결제 수락 설정';
COMMENT ON COLUMN user_gdc_settings.gdc_accepted IS 'TRUE = K-Market GDC 결제 가능';


-- ================================================================
-- SECTION 2: search_entities() RPC
-- SP-USERS-v2_0 STEP 05 에서 호출
-- ================================================================

CREATE OR REPLACE FUNCTION search_entities(
  p_entity_type  text    DEFAULT NULL,   -- 'person'|'org'|'concept'|'thing'|NULL
  p_keyword      text    DEFAULT NULL,   -- 이름/업종/서비스 통합 검색
  p_occupation   text    DEFAULT NULL,   -- 업종 필터
  p_address      text    DEFAULT NULL,   -- 주소 힌트 (ILIKE)
  p_gdc_only     boolean DEFAULT false,  -- GDC 결제 가능 업체만
  p_trust_min    text    DEFAULT NULL,   -- 최소 신뢰 등급 ('L1'|'L2'|'L3')
  p_lat          float8  DEFAULT NULL,   -- 기준 위도 (거리 계산용)
  p_lng          float8  DEFAULT NULL,   -- 기준 경도
  p_sort         text    DEFAULT 'rating', -- 'distance'|'rating'|'review_count'
  p_limit        int     DEFAULT 10,
  p_offset       int     DEFAULT 0,
  p_exclude_guid text    DEFAULT NULL    -- 요청자 본인 제외
)
RETURNS TABLE (
  guid          text,
  entity_type   text,
  name          text,
  occupation    text,
  services      text[],
  address       text,
  website       text,
  is_public     boolean,
  extra         jsonb,
  trust_level   text,
  gdc_accepted  boolean,
  rating_avg    numeric,
  review_count  integer,
  lat           numeric,
  lng           numeric,
  distance_km   float8
)
LANGUAGE sql STABLE
AS $$
  -- 신뢰 등급 정수 변환 (정렬·필터용)
  WITH trust_order AS (
    SELECT 'L0'::text AS lvl, 0 AS ord UNION ALL
    SELECT 'L1',              1        UNION ALL
    SELECT 'L2',              2        UNION ALL
    SELECT 'L3',              3
  ),
  base AS (
    SELECT
      up.guid,
      up.entity_type,
      up.name,
      up.occupation,
      up.services,
      up.address,
      up.website,
      up.is_public,
      up.extra,
      COALESCE(utl.trust_level, 'L0')  AS trust_level,
      COALESCE(ugs.gdc_accepted, false) AS gdc_accepted,
      COALESCE(sr.weighted_avg,  0)     AS rating_avg,
      COALESCE(sr.review_count,  0)     AS review_count,
      ll.lat,
      ll.lng,
      -- Haversine 거리 (km)
      CASE
        WHEN p_lat IS NOT NULL AND p_lng IS NOT NULL AND ll.lat IS NOT NULL
        THEN 2.0 * 6371.0 * asin(sqrt(
               power(sin(radians(ll.lat - p_lat) / 2.0), 2) +
               cos(radians(p_lat)) * cos(radians(ll.lat)) *
               power(sin(radians(ll.lng - p_lng) / 2.0), 2)
             ))
        ELSE NULL
      END AS distance_km,
      COALESCE(to_.ord, 0) AS trust_ord
    FROM user_profiles up
    JOIN users u
      ON up.guid = u.guid
    LEFT JOIN user_trust_levels utl
      ON utl.guid = up.guid
    LEFT JOIN trust_order to_
      ON to_.lvl = COALESCE(utl.trust_level, 'L0')
    LEFT JOIN user_gdc_settings ugs
      ON ugs.guid = up.guid
    LEFT JOIN seller_ratings sr
      ON sr.seller_guid = up.guid
    LEFT JOIN LATERAL (
      SELECT lat, lng, address
      FROM   location_log
      WHERE  user_guid = up.guid
      ORDER  BY recorded_at DESC
      LIMIT  1
    ) ll ON TRUE
    WHERE
      up.is_public = TRUE
      -- 요청자 본인 제외
      AND (p_exclude_guid IS NULL OR up.guid <> p_exclude_guid)
      -- entity_type 필터
      AND (p_entity_type IS NULL OR up.entity_type = p_entity_type)
      -- 업종 필터
      AND (p_occupation IS NULL
           OR up.occupation ILIKE '%' || p_occupation || '%')
      -- 통합 키워드 (이름/업종/서비스)
      AND (p_keyword IS NULL
           OR up.name       ILIKE '%' || p_keyword || '%'
           OR up.occupation ILIKE '%' || p_keyword || '%'
           OR EXISTS (
               SELECT 1 FROM unnest(up.services) svc
               WHERE svc ILIKE '%' || p_keyword || '%'
             ))
      -- 주소 힌트 (user_profiles.address 또는 location_log.address)
      AND (p_address IS NULL
           OR up.address ILIKE '%' || p_address || '%'
           OR ll.address  ILIKE '%' || p_address || '%')
      -- GDC 필터
      AND (p_gdc_only = FALSE OR ugs.gdc_accepted = TRUE)
      -- 최소 신뢰 등급
      AND (p_trust_min IS NULL
           OR COALESCE(to_.ord, 0) >= (
             SELECT ord FROM trust_order WHERE lvl = p_trust_min
           ))
  )
  SELECT
    guid, entity_type, name, occupation, services,
    address, website, is_public, extra,
    trust_level, gdc_accepted,
    rating_avg::numeric, review_count::integer,
    lat, lng, distance_km
  FROM base
  ORDER BY
    -- 거리순 (lat/lng 제공 시)
    CASE WHEN p_sort = 'distance' AND distance_km IS NOT NULL
         THEN distance_km END ASC NULLS LAST,
    -- 평점순
    CASE WHEN p_sort = 'rating'
         THEN rating_avg END DESC NULLS LAST,
    -- 리뷰 수순
    CASE WHEN p_sort = 'review_count'
         THEN review_count END DESC NULLS LAST,
    -- 보조 정렬: 신뢰 등급 내림차순
    trust_ord DESC
  LIMIT  p_limit
  OFFSET p_offset;
$$;

COMMENT ON FUNCTION search_entities IS
  'users.hondi.net 엔티티 통합 검색 RPC.
   기존 테이블(user_profiles, seller_ratings, location_log)을
   LEFT JOIN하여 거리·평점·신뢰등급 정렬을 지원한다.';


-- ================================================================
-- SECTION 3: worker.js 에 추가할 엔드포인트 코드 (SQL 주석으로 첨부)
-- ================================================================
-- 아래는 Cloudflare Worker(worker.js)의 라우팅 블록과
-- 핸들러 함수 전체를 주석으로 제공합니다.
-- worker.js의 라우팅 섹션(pathname 분기)에 삽입하십시오.
-- ================================================================

/*
──────────────────────────────────────────────────────────────────
[worker.js 라우팅 삽입 위치]
기존 라우팅 블록 마지막 줄 (404 반환 직전) 에 추가:

    // ── v4.7: users 엔티티 검색 ──────────────────────────────
    if (pathname === '/users/search') return handleUsersSearch(bodyText, env, corsHeaders);
    if (pathname === '/users/public') return handleUsersPublic(bodyText, env, corsHeaders);

──────────────────────────────────────────────────────────────────
[ALLOWED_ORIGINS 에 추가]
    'https://users.hondi.net',

──────────────────────────────────────────────────────────────────
[핸들러 함수 — worker.js 파일 끝에 추가]
──────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════
// v4.7 — /users/search
// SUBSYSTEM 또는 HUMAN 이 엔티티 검색을 요청할 때 호출
// SP-USERS-v2_0 STEP 00 참조
// ═══════════════════════════════════════════════════════════

async function handleUsersSearch(bodyText, env, corsHeaders) {
  let body;
  try { body = JSON.parse(bodyText); }
  catch { return _err(400, 'INVALID_JSON', 'JSON 파싱 실패', corsHeaders); }

  const caller = body.caller || 'unknown';
  const isHuman = !caller || caller.startsWith('users-');

  // ── location 미제공 시 location_log에서 최신 위치 조회 ──
  if (!body.location && body.requester_guid) {
    try {
      const key = env.SUPABASE_KEY || _supabaseAnonKey();
      const res = await fetch(
        SUPABASE_URL + `/rest/v1/location_log`
        + `?user_guid=eq.${encodeURIComponent(body.requester_guid)}`
        + `&order=recorded_at.desc&limit=1&select=lat,lng,address`,
        { headers: { apikey: key, Authorization: 'Bearer ' + key } }
      );
      const rows = await res.json().catch(() => []);
      if (rows?.[0]) body.location = rows[0];
    } catch (e) {
      console.warn('[UsersSearch] 위치 조회 실패:', e.message);
    }
  }

  // ── SUBSYSTEM + 완전한 filter → RPC 직접 호출 (LLM 생략) ──
  if (!isHuman && body.filter?.entity_type) {
    return await _usersDirectSearch(body, env, corsHeaders);
  }

  // ── HUMAN 또는 filter 불완전 → AI Agent (LLM) 호출 ──
  return await _usersAISearch(body, env, corsHeaders);
}

// ── Supabase RPC 직접 호출 (LLM 없음) ─────────────────────────
async function _usersDirectSearch(body, env, corsHeaders) {
  const key  = env.SUPABASE_KEY || _supabaseAnonKey();
  const f    = body.filter || {};
  const loc  = body.location || {};

  const rpcBody = {
    p_entity_type:  f.entity_type  || null,
    p_keyword:      body.query     || null,
    p_occupation:   f.occupation   || null,
    p_address:      loc.address    || null,
    p_gdc_only:     f.gdc_only     || false,
    p_trust_min:    f.trust_min    || null,
    p_lat:          loc.lat        || null,
    p_lng:          loc.lng        || null,
    p_sort:         body.sort      || 'rating',
    p_limit:        body.limit     || 10,
    p_offset:       body.offset    || 0,
    p_exclude_guid: body.requester_guid || null,
  };

  try {
    const res  = await fetch(SUPABASE_URL + '/rest/v1/rpc/search_entities', {
      method:  'POST',
      headers: {
        apikey:          key,
        Authorization:   'Bearer ' + key,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify(rpcBody),
    });
    const rows = await res.json().catch(() => []);

    return new Response(JSON.stringify({
      status:       rows?.length ? 'ok' : 'no_result',
      caller_echo:  body.caller,
      intent:       'TRANSACT',
      sort_applied: body.sort || 'rating',
      results:      rows || [],
      total_count:  rows?.length || 0,
      gwp_action:   { type: 'DISPLAY_RESULTS' },
    }), { status: 200, headers: corsHeaders });

  } catch (e) {
    return _err(502, 'DB_ERROR', e.message, corsHeaders);
  }
}

// ── LLM(AI Agent) 호출 — 자연언어 해석 필요 시 ───────────────
async function _usersAISearch(body, env, corsHeaders) {
  // SP-USERS-v2_0 로드 (GitHub raw URL)
  let systemPrompt = '';
  try {
    const spRes = await fetch(
      'https://raw.githubusercontent.com/Openhash-Gopang/users/main/SP-USERS-v2_0.txt'
      + '?t=' + Date.now()
    );
    if (spRes.ok) systemPrompt = await spRes.text();
  } catch {}

  if (!systemPrompt) {
    systemPrompt = '당신은 Gopang Users 엔티티 검색 에이전트입니다. 반드시 JSON으로만 응답하십시오.';
  }

  const loc = body.location || {};
  const contextNote = [
    `caller: ${body.caller || 'unknown'}`,
    `requester_guid: ${body.requester_guid || 'unknown'}`,
    loc.lat ? `location: lat=${loc.lat}, lng=${loc.lng}, address=${loc.address || ''}` : '',
    `sort: ${body.sort || 'rating'}`,
  ].filter(Boolean).join('\n');

  const messages = [
    { role: 'user', content: body.query || JSON.stringify(body) },
  ];

  try {
    const aiRes = await fetch(DEEPSEEK_URL, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        Authorization:   `Bearer ${env.DEEPSEEK_API_KEY}`,
      },
      body: JSON.stringify({
        model:    DEEPSEEK_MODEL,
        max_tokens: 2000,
        messages: [
          { role: 'system', content: systemPrompt + '\n\n[컨텍스트]\n' + contextNote },
          ...messages,
        ],
      }),
    });
    const aiData = await aiRes.json();
    const reply  = aiData.choices?.[0]?.message?.content || '{}';

    // AI 응답이 search_entities RPC 파라미터를 담은 JSON이면
    // 즉시 RPC 호출로 전환 (두 번의 왕복 최소화)
    let parsed = null;
    try { parsed = JSON.parse(reply); } catch {}

    if (parsed?.rpc_params) {
      // AI가 rpc_params 블록을 반환한 경우 직접 RPC 호출
      const syntheticBody = {
        caller:         body.caller,
        filter:         parsed.rpc_params,
        location:       body.location,
        sort:           parsed.rpc_params.sort || body.sort,
        limit:          body.limit,
        offset:         body.offset,
        requester_guid: body.requester_guid,
      };
      return await _usersDirectSearch(syntheticBody, env, corsHeaders);
    }

    // AI가 최종 JSON 응답을 직접 반환한 경우 그대로 전달
    if (parsed?.status) {
      if (!parsed.caller_echo) parsed.caller_echo = body.caller;
      return new Response(JSON.stringify(parsed),
        { status: 200, headers: corsHeaders });
    }

    return new Response(reply, { status: 200, headers: corsHeaders });

  } catch (e) {
    return _err(502, 'AI_ERROR', e.message, corsHeaders);
  }
}

// ═══════════════════════════════════════════════════════════
// v4.7 — /users/public
// is_public 토글: user_profiles.is_public 업데이트
// ═══════════════════════════════════════════════════════════

async function handleUsersPublic(bodyText, env, corsHeaders) {
  let body;
  try { body = JSON.parse(bodyText); }
  catch { return _err(400, 'INVALID_JSON', 'JSON 파싱 실패', corsHeaders); }

  const { guid, is_public } = body;
  if (!guid || is_public === undefined)
    return _err(400, 'MISSING_FIELD', 'guid, is_public 필수', corsHeaders);

  const key = env.SUPABASE_KEY || _supabaseAnonKey();
  try {
    const res = await fetch(
      SUPABASE_URL + `/rest/v1/user_profiles?guid=eq.${encodeURIComponent(guid)}`,
      {
        method:  'PATCH',
        headers: {
          apikey:          key,
          Authorization:   'Bearer ' + key,
          'Content-Type':  'application/json',
          Prefer:          'return=minimal',
        },
        body: JSON.stringify({ is_public, updated_at: new Date().toISOString() }),
      }
    );
    if (!res.ok) throw new Error(`Supabase PATCH ${res.status}`);
    return new Response(
      JSON.stringify({ ok: true, guid, is_public }),
      { status: 200, headers: corsHeaders }
    );
  } catch (e) {
    return _err(502, 'DB_ERROR', e.message, corsHeaders);
  }
}

*/

-- ================================================================
-- SECTION 4: 기본 데이터 — 신뢰 등급 초기화
-- 기존 users 테이블의 모든 사용자에게 L0 기본 등급 부여
-- (이미 등록된 사용자 데이터 보존)
-- ================================================================

INSERT INTO user_trust_levels (guid, trust_level)
SELECT guid, 'L0'
FROM   users
ON CONFLICT (guid) DO NOTHING;

INSERT INTO user_gdc_settings (guid, gdc_accepted)
SELECT guid, false
FROM   users
ON CONFLICT (guid) DO NOTHING;

-- ================================================================
-- SECTION 5: Row Level Security (선택적 적용)
-- ================================================================

ALTER TABLE user_nicknames    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_trust_levels ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_gdc_settings ENABLE ROW LEVEL SECURITY;

-- 읽기: 누구나 (검색 가능)
CREATE POLICY IF NOT EXISTS "nicknames_select_public"
  ON user_nicknames FOR SELECT USING (true);

CREATE POLICY IF NOT EXISTS "trust_select_public"
  ON user_trust_levels FOR SELECT USING (true);

CREATE POLICY IF NOT EXISTS "gdc_select_public"
  ON user_gdc_settings FOR SELECT USING (true);

-- 쓰기: Service Role(Worker)만 허용
-- (anon key로는 INSERT/UPDATE 불가 → Worker의 service key 사용)
CREATE POLICY IF NOT EXISTS "nicknames_write_service"
  ON user_nicknames FOR ALL
  USING (auth.role() = 'service_role');

CREATE POLICY IF NOT EXISTS "trust_write_service"
  ON user_trust_levels FOR ALL
  USING (auth.role() = 'service_role');

CREATE POLICY IF NOT EXISTS "gdc_write_service"
  ON user_gdc_settings FOR ALL
  USING (auth.role() = 'service_role');

-- search_entities() 는 SECURITY DEFINER 없이 STABLE로 선언했으므로
-- anon role에서 호출 가능 (user_profiles.is_public = TRUE 필터가 보호)
GRANT EXECUTE ON FUNCTION search_entities TO anon, authenticated;
