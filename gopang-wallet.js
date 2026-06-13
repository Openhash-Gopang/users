/**
 * gopang-wallet.js — Gopang 클라이언트 지갑 공통 모듈
 * Version  : 1.0.0
 * Spec     : GDUDA 5-Layer / OpenHash L1
 * Crypto   : Web Crypto API (Ed25519) — 외부 의존 없음
 * Storage  : 개인키 → IndexedDB (AES-GCM 암호화) + localStorage 폴백
 * 사용법   : <script src="gopang-wallet.js"></script>
 *             const wallet = await GopangWallet.load();
 */

'use strict';

(function (global) {

  /* ────────────────────────────────────────────────
   *  상수
   * ──────────────────────────────────────────────── */
  const VERSION          = '2.0.0';
  const IDB_NAME         = 'gopang-wallet';
  const IDB_VER          = 2;               // v2.0: hash_chain store 추가
  const IDB_STORE        = 'keys';           // 개인키·재무상태 저장
  const IDB_STORE_CHAIN  = 'hash_chain';     // Hash Chain 이력 저장 (keys와 분리)
  const IDB_KEY_ID       = 'ed25519-main';
  const IDB_FS_KEY       = 'financial_state'; // 로컬 재무제표 키
  const LS_PUBKEY        = 'gopang_wallet_pubkey';
  const LS_HANDLE        = 'gopang_wallet_handle';
  const SUPABASE_URL     = 'https://ebbecjfrwaswbdybbgiu.supabase.co';
  const WORKER_URL       = 'https://gopang-proxy.tensor-city.workers.dev';

  /* ────────────────────────────────────────────────
   *  유틸리티
   * ──────────────────────────────────────────────── */

  /** ArrayBuffer → Base64URL */
  function bufToB64u(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /** Base64URL → Uint8Array */
  function b64uToBuf(b64u) {
    const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  }

  /** Uint8Array → Hex */
  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** 현재 Unix 타임스탬프 (초) */
  function nowSec() { return Math.floor(Date.now() / 1000); }

  /** SHA-256 해시 → ArrayBuffer */
  async function sha256(data) {
    const buf = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;
    return crypto.subtle.digest('SHA-256', buf);
  }

  /** nickname_hash 생성 — SHA-256("ko:닉네임") → hex */
  async function nicknameHash(nickname, lang = 'ko') {
    const raw = `${lang}:${nickname}`;
    const buf = await sha256(raw);
    return bufToHex(buf);
  }

  /* ────────────────────────────────────────────────
   *  IndexedDB 헬퍼
   * ──────────────────────────────────────────────── */

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, IDB_VER);
      req.onupgradeneeded = e => {
        const db      = e.target.result;
        const oldVer  = e.oldVersion;
        // v1: keys store
        if (oldVer < 1) db.createObjectStore(IDB_STORE);
        // v2: hash_chain store (keys와 완전 분리)
        if (oldVer < 2) db.createObjectStore(IDB_STORE_CHAIN, { keyPath: 'height' });
      };
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  // hash_chain store 전용 헬퍼
  async function idbChainPut(db, record) {
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE_CHAIN, 'readwrite');
      const req = tx.objectStore(IDB_STORE_CHAIN).put(record);
      req.onsuccess = () => resolve();
      req.onerror   = e  => reject(e.target.error);
    });
  }

  async function idbChainGetLast(db) {
    return new Promise((resolve, reject) => {
      const tx     = db.transaction(IDB_STORE_CHAIN, 'readonly');
      const store  = tx.objectStore(IDB_STORE_CHAIN);
      const req    = store.openCursor(null, 'prev'); // 내림차순 → 최신
      req.onsuccess = e => resolve(e.target.result?.value ?? null);
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function idbChainGetAll(db) {
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE_CHAIN, 'readonly');
      const req = tx.objectStore(IDB_STORE_CHAIN).getAll();
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function idbGet(db, key) {
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(key);
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function idbPut(db, key, value) {
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readwrite');
      const req = tx.objectStore(IDB_STORE).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror   = e  => reject(e.target.error);
    });
  }

  async function idbDel(db, key) {
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readwrite');
      const req = tx.objectStore(IDB_STORE).delete(key);
      req.onsuccess = () => resolve();
      req.onerror   = e  => reject(e.target.error);
    });
  }

  /* ────────────────────────────────────────────────
   *  AES-GCM 래퍼 — 개인키 암호화 저장용
   *  passphrase 없이 사용 시 기기 고유 entropy로 대체
   * ──────────────────────────────────────────────── */

  async function deriveAesKey(passphrase, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase),
      'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
  }

  async function encryptPrivKey(privKeyBuf, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const aes  = await deriveAesKey(passphrase, salt);
    const enc  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, privKeyBuf);
    // 저장 포맷: salt(16) + iv(12) + ciphertext
    const out  = new Uint8Array(16 + 12 + enc.byteLength);
    out.set(salt, 0);
    out.set(iv,   16);
    out.set(new Uint8Array(enc), 28);
    return out.buffer;
  }

  async function decryptPrivKey(encBuf, passphrase) {
    const data   = new Uint8Array(encBuf);
    const salt   = data.slice(0, 16);
    const iv     = data.slice(16, 28);
    const cipher = data.slice(28);
    const aes    = await deriveAesKey(passphrase, salt);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, cipher);
  }

  /* ────────────────────────────────────────────────
   *  Ed25519 키페어 생성 및 관리
   * ──────────────────────────────────────────────── */

  /**
   * 새 Ed25519 키페어 생성
   * @returns {{ publicKeyB64u, privateKeyB64u, publicKeyRaw }}
   */
  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,         // extractable
      ['sign', 'verify']
    );

    const pubRaw  = await crypto.subtle.exportKey('raw',  keyPair.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk',  keyPair.privateKey);
    // JWK d 값이 실질적 private scalar
    const privRaw = b64uToBuf(privJwk.d);

    return {
      publicKey    : keyPair.publicKey,
      privateKey   : keyPair.privateKey,
      publicKeyB64u: bufToB64u(pubRaw),
      publicKeyHex : bufToHex(pubRaw),
      privateKeyB64u: privJwk.d,  // JWK d (Base64URL)
    };
  }

  /**
   * Ed25519 서명
   * @param {CryptoKey} privateKey
   * @param {string|ArrayBuffer} payload  — 문자열이면 UTF-8 인코딩
   * @returns {string} Base64URL 서명
   */
  async function sign(privateKey, payload) {
    const data = typeof payload === 'string'
      ? new TextEncoder().encode(payload)
      : payload;
    const sig = await crypto.subtle.sign('Ed25519', privateKey, data);
    return bufToB64u(sig);
  }

  /**
   * Ed25519 서명 검증
   * @param {string} publicKeyB64u  — Base64URL 공개키
   * @param {string|ArrayBuffer} payload
   * @param {string} signatureB64u  — Base64URL 서명
   * @returns {boolean}
   */
  async function verify(publicKeyB64u, payload, signatureB64u) {
    const pubKey = await crypto.subtle.importKey(
      'raw', b64uToBuf(publicKeyB64u),
      { name: 'Ed25519' }, false, ['verify']
    );
    const data = typeof payload === 'string'
      ? new TextEncoder().encode(payload)
      : payload;
    const sig = b64uToBuf(signatureB64u);
    return crypto.subtle.verify('Ed25519', pubKey, sig, data);
  }

  /* ────────────────────────────────────────────────
   *  TX (Transaction) 빌더
   * ──────────────────────────────────────────────── */

  /**
   * 서명된 TX 객체 생성
   *
   * TX 구조:
   * {
   *   version   : 1,
   *   type      : 'USER_REGISTER' | 'GDC_TRANSFER' | 'BIZ_ORDER' | ...,
   *   from_guid : string (IPv6 형식),
   *   to_guid   : string | null,
   *   amount    : number | null,
   *   payload   : object (자유 형식),
   *   timestamp : number (Unix 초),
   *   nonce     : string (hex-16),
   *   signature : string (Base64URL, Ed25519)
   *   pubkey    : string (Base64URL, 공개키)
   * }
   */
  async function buildTx(privateKey, pubKeyB64u, fromGuid, txType, payload, opts = {}) {
    const nonce = bufToHex(crypto.getRandomValues(new Uint8Array(8)));
    const ts    = nowSec();

    const body = {
      version  : 1,
      type     : txType,
      from_guid: fromGuid,
      to_guid  : opts.toGuid   ?? null,
      amount   : opts.amount   ?? null,
      payload,
      timestamp: ts,
      nonce,
      pubkey   : pubKeyB64u,
    };

    // 서명 대상: JSON 직렬화 (signature 키 제외)
    const sigTarget = JSON.stringify(body);
    const signature = await sign(privateKey, sigTarget);

    return { ...body, signature };
  }

  /* ────────────────────────────────────────────────
   *  결정적 직렬화 (prev_settle_hash 계산용)
   *  JSON.stringify는 key 순서 비결정적 → 반드시 sortedStringify 사용
   * ──────────────────────────────────────────────── */

  function sortedStringify(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return JSON.stringify(obj);
    }
    const sorted = {};
    Object.keys(obj).sort().forEach(k => {
      sorted[k] = obj[k];
    });
    // 재귀적으로 중첩 객체도 정렬
    return '{' + Object.keys(sorted).map(k =>
      JSON.stringify(k) + ':' + sortedStringify(sorted[k])
    ).join(',') + '}';
  }

  /**
   * 재무 상태 객체 → prev_settle_hash 계산
   * @param {Object} financialState  — { 'bs-cash': 숫자, 'pl-purchase': 숫자, ... }
   * @returns {string} hex SHA-256
   */
  async function computePrevSettleHash(financialState) {
    const canonical = sortedStringify(financialState || {});
    const buf = await sha256(canonical);
    return bufToHex(buf);
  }

  /**
   * UTXO 방식 TX 빌더 — L1 /api/tx 형식
   * gopang-app.js _gwpSignExecute()에서 wallet.buildTxWithPrevHash() 호출
   *
   * @param {Object} opts
   *   opts.buyerGuid       — 구매자 primary_guid
   *   opts.sellerGuid      — 판매자 primary_guid
   *   opts.total           — 합계 (구매자 지불)
   *   opts.sellerNet       — 판매자 순수입 (플랫폼 수수료 제외)
   *   opts.platformFee     — 플랫폼 수수료
   *   opts.financialState  — 현재 재무 상태 객체 (prev_settle_hash 계산용)
   *   opts.items           — 품목 배열
   * @returns {Object} UTXO tx (buyer_sig 제외)
   */
  async function buildTxWithPrevHash({
    buyerGuid, sellerGuid, total, sellerNet, platformFee,
    financialState, items, prevSettleHash,
  }) {
    // prevSettleHash는 호출자(sign → buildPrevSettleHash)가 주입
    // L1 검증 기준: prev_settle_hash === 직전 블록의 content_hash
    const nonce     = bufToHex(crypto.getRandomValues(new Uint8Array(8)));
    const timestamp = nowSec();

    const tx = {
      version: 1,
      input: {
        owner_guid:      buyerGuid,
        prev_settle_hash: prevSettleHash,
        balance_claimed: (financialState?.['bs-cash'] ?? 0),
      },
      outputs: [
        { recipient_guid: sellerGuid,       amount: sellerNet   },
        { recipient_guid: 'gopang-platform', amount: platformFee },
      ],
      items:     items || [],
      nonce,
      timestamp,
    };

    return { tx, prevSettleHash };
  }

  /**
   * tx_hash 계산 후 Ed25519 서명 → buyer_sig 반환
   * @param {CryptoKey} privateKey
   * @param {Object} tx  — buildTxWithPrevHash() 반환값의 tx
   * @returns {{ tx_hash: string, buyer_sig: string }}
   */
  async function signTx(privateKey, tx) {
    const txHash   = bufToHex(await sha256(sortedStringify(tx)));
    const sigBuf   = await crypto.subtle.sign(
      'Ed25519', privateKey, new TextEncoder().encode(txHash)
    );
    const buyerSig = bufToB64u(sigBuf);
    return { tx_hash: txHash, buyer_sig: buyerSig };
  }

  /* ────────────────────────────────────────────────
   *  Hash Chain 관리
   *  h_i = SHA-256(h_{i-1} ∥ tx_hash ∥ block_hash ∥ height)
   * ──────────────────────────────────────────────── */

  /**
   * Hash Chain에 새 항목 추가 (거래 완료 후 호출)
   * @param {IDBDatabase} db
   * @param {Object} opts
   *   opts.prevSettleHash  — 거래 출발 재무 상태 해시
   *   opts.newSettleHash   — 거래 완료 후 재무 상태 해시
   *   opts.txHash          — tx_hash (SHA-256(sortedStringify(tx)))
   *   opts.blockHash       — L1 block_hash
   *   opts.blockId         — L1 block_id
   * @returns {Object} 새 chain record
   */
  async function appendHashChain(db, {
    txHash,
    blockHash,
    blockId      = null,
    pdvSessionId = null,
    pdvType      = null,
  }) {
    const last          = await idbChainGetLast(db);
    const height        = (last?.height ?? -1) + 1;
    const prevLocalHash = last?.local_hash ?? '0'.repeat(64);

    // 공식 불변 (v3.0 확정)
    // h_i = SHA-256(h_{i-1} ∥ tx_hash ∥ block_hash ∥ height)
    const chainInput = prevLocalHash + txHash + blockHash + String(height);
    const localHash  = bufToHex(await sha256(chainInput));

    const record = {
      height,
      local_hash:      localHash,
      prev_local_hash: prevLocalHash,
      tx_hash:         txHash,
      block_hash:      blockHash,
      block_id:        blockId,
      recorded_at:     new Date().toISOString(),
      pdv_session_id:  pdvSessionId,
      pdv_type:        pdvType,
      pdv_anchored:    false,
      // prev_settle_hash: @deprecated — 제거됨
      // new_settle_hash:  @deprecated — 제거됨
    };

    await idbChainPut(db, record);
    return record;
  }

  /* ────────────────────────────────────────────────
   *  GopangWallet 클래스
   * ──────────────────────────────────────────────── */

  class GopangWallet {

    constructor({ publicKey, privateKey, publicKeyB64u, publicKeyHex, handle, guid }) {
      this._pubKey     = publicKey;
      this._privKey    = privateKey;
      this.publicKeyB64u = publicKeyB64u;
      this.publicKeyHex  = publicKeyHex;
      this.handle      = handle ?? null;   // @닉네임#태그
      this.guid        = guid   ?? null;   // user_profiles.current_ipv6
    }

    /* ── 서명 ── */
    async sign(payload) {
      return sign(this._privKey, payload);
    }

    /* ── TX 생성 ── */
    async buildTx(txType, payload, opts = {}) {
      if (!this.guid) throw new Error('wallet: guid(IPv6)가 설정되지 않았습니다.');
      return buildTx(this._privKey, this.publicKeyB64u, this.guid, txType, payload, opts);
    }

    /* ── 공개키로 서명 검증 (정적으로도 호출 가능) ── */
    async verify(payload, signatureB64u) {
      return verify(this.publicKeyB64u, payload, signatureB64u);
    }

    /* ── handle / guid 설정 ── */
    setIdentity({ handle, guid }) {
      if (handle) {
        this.handle = handle;
        localStorage.setItem(LS_HANDLE, handle);
      }
      if (guid) this.guid = guid;
    }

    /* ── Supabase 공개키 등록 (Worker 경유) ── */
    async registerPublicKey(anonKey) {
      if (!this.guid) throw new Error('wallet: guid가 없습니다.');
      const res = await fetch(`${SUPABASE_URL}/rest/v1/user_profiles?current_ipv6=eq.${this.guid}`, {
        method : 'PATCH',
        headers: {
          'Content-Type' : 'application/json',
          'apikey'       : anonKey,
          'Authorization': `Bearer ${anonKey}`,
          'Prefer'       : 'return=minimal',
        },
        body: JSON.stringify({ pubkey_ed25519: this.publicKeyB64u }),
      });
      if (!res.ok) throw new Error(`공개키 등록 실패: ${res.status}`);
      return true;
    }

    /* ── 지갑 정보 요약 ── */
    summary() {
      return {
        version  : VERSION,
        handle   : this.handle,
        guid     : this.guid,
        pubkey   : this.publicKeyB64u,
        pubkeyHex: this.publicKeyHex,
      };
    }

    /* ────────────────────────────────────────────────
     *  v2.0 인스턴스 메서드
     * ──────────────────────────────────────────────── */

    /**
     * 현재 로컬 재무 상태 조회 (IndexedDB keys store)
     * @returns {Object}  { 'bs-cash': 숫자, ... }
     */
    async getFinancialState() {
      try {
        const db  = await openDB();
        const rec = await idbGet(db, IDB_FS_KEY);
        return rec?.state || {};
      } catch { return {}; }
    }

    /**
     * bs-cash 잔액 조회
     * @returns {number}
     */
    async getBalance() {
      const fs = await this.getFinancialState();
      return parseFloat(fs['bs-cash'] ?? '0') || 0;
    }

    /**
     * prev_settle_hash 반환 — L1 main.pb.js 3단계 검증 기준
     * L1은 prev_settle_hash === 직전 블록의 content_hash 를 검증함.
     * block_hash null = 최초 거래 (L1 블록 없음) → L1이 자체 처리.
     * @returns {{ prevSettleHash: string|null, financialState: Object }}
     */
    async buildPrevSettleHash() {
      const db  = await openDB();
      const rec = await idbGet(db, IDB_FS_KEY);
      const financialState = rec?.state || {};
      const prevSettleHash = rec?.block_hash || null;
      // null = 최초 거래 → L1이 latestBlock 없을 때 검증 건너뜀
      return { prevSettleHash, financialState };
    }

    /**
     * UTXO tx 빌드 + Ed25519 서명 — gopang-app.js _gwpSignExecute()에서 호출
     * GWP_SIGN_REQUEST의 tx 객체를 받아 prev_settle_hash 주입 후 서명
     *
     * @param {Object} rawTx  — GWP_SIGN_REQUEST에서 수신한 tx
     *   rawTx.outputs        — [{ recipient_guid, amount }]
     *   rawTx.items          — 품목 배열
     * @returns {Object} signedTx  — Worker /biz/order POST 본문
     */
    async sign(rawTx) {
      if (!this.guid) throw new Error('[Wallet] guid(IPv6)가 설정되지 않았습니다.');

      const { financialState, prevSettleHash } = await this.buildPrevSettleHash();

      // outputs에서 판매자·플랫폼 분리
      const sellerOut   = rawTx.outputs?.find(o => o.recipient_guid !== 'gopang-platform');
      const platformOut = rawTx.outputs?.find(o => o.recipient_guid === 'gopang-platform');
      const sellerNet   = sellerOut?.amount   || 0;
      const platformFee = platformOut?.amount || 0;

      // UTXO tx 구성 (prev_settle_hash 주입)
      const { tx } = await buildTxWithPrevHash({
        buyerGuid:      this.guid,
        sellerGuid:     sellerOut?.recipient_guid || rawTx.seller_guid || '',
        total:          rawTx.total || sellerNet + platformFee,
        sellerNet,
        platformFee,
        financialState,
        items:          rawTx.items || [],
        prevSettleHash,   // ← block_hash 기반 값 주입
      });

      // tx_hash 계산 + Ed25519 서명
      const { tx_hash, buyer_sig } = await signTx(this._privKey, tx);

      return {
        tx,
        tx_hash,
        buyer_sig,
        buyer_public_key: this.publicKeyB64u,
        prev_settle_hash: prevSettleHash,      // L1 검증용
      };
    }

    /**
     * L1 청구권 수신 → 재무 상태 자기갱신 + Hash Chain 기록
     * gopang-app.js GWP_DONE 핸들러에서 호출 (STEP 24)
     *
     * @param {Object} opts
     *   opts.block_hash   — L1 block_hash
     *   opts.block_id     — L1 block_id
     *   opts.claims       — [{ direction, amount, fs_account, expires_at, ... }]
     *   opts.tx_hash      — tx_hash (없으면 block_hash로 대체)
     */
    async redeemClaim({
      block_hash,
      block_id       = null,
      claims         = [],
      tx_hash,
      pdv_session_id = null,
      pdv_type       = null,
    }) {
      if (!block_hash) throw new Error('[Wallet] block_hash 없음');

      const db = await openDB();

      // 현재 재무 상태 로드
      const fsRec = await idbGet(db, IDB_FS_KEY);
      const fs    = fsRec?.state || {};

      // 만료 확인 + 청구권 적용
      const now = Date.now();
      let applied = 0;
      for (const claim of claims) {
        if (claim.expires_at && new Date(claim.expires_at).getTime() < now) {
          console.warn('[Wallet] 만료된 청구권 무시:', claim);
          continue;
        }
        const acc = claim.fs_account || 'bs-cash';
        const cur = parseFloat(fs[acc] ?? '0') || 0;
        if (claim.direction === 'credit') {
          fs[acc] = cur + (claim.amount || 0);
        } else if (claim.direction === 'debit') {
          // pl-purchase: 누적 지출액(양수) — cur + amount
          // bs-cash: 잔액 감소 — 별도 처리
          if (acc === 'pl-purchase') {
            fs[acc] = cur + (claim.amount || 0);
          } else {
            fs[acc] = cur - (claim.amount || 0);
          }
        }
        // bs-cash 동기화 (pl 계정 변동 시)
        if (acc !== 'bs-cash') {
          const bsCash = parseFloat(fs['bs-cash'] ?? '0') || 0;
          if (claim.direction === 'credit') fs['bs-cash'] = bsCash + (claim.amount || 0);
          else                              fs['bs-cash'] = bsCash - (claim.amount || 0);
        }
        applied++;
      }

      // 갱신된 재무 상태 저장
      await idbPut(db, IDB_FS_KEY, {
        state:     fs,
        updatedAt: new Date().toISOString(),
        block_hash,
      });

      // Hash Chain 기록 (v3.0: pdv_session_id 연동)
      const chainRec = await appendHashChain(db, {
        txHash:       tx_hash || block_hash,
        blockHash:    block_hash,
        blockId:      block_id,
        pdvSessionId: pdv_session_id,
        pdvType:      pdv_type,
      });

      console.info('[Wallet] redeemClaim 완료',
        '| height:', chainRec.height,
        '| applied:', applied,
        '| bs-cash:', fs['bs-cash'],
        '| pdv_session_id:', pdv_session_id?.slice(0, 8) || 'none');

      return { fs, chainRec, applied };
    }

    /**
     * Hash Chain 전체 조회
     * @returns {Array} chain 이력 배열 (height 오름차순)
     */
    async getHashChain() {
      const db = await openDB();
      const records = await idbChainGetAll(db);
      return records.sort((a, b) => a.height - b.height);
    }

    /**
     * Hash Chain 연속성 검증
     * @returns {{ valid: boolean, broken_at: number|null }}
     */
    async verifyChain() {
      const chain = await this.getHashChain();
      for (let i = 1; i < chain.length; i++) {
        const cur  = chain[i];
        const prev = chain[i - 1];

        // 1) 연결 확인
        if (cur.prev_local_hash !== prev.local_hash) {
          return { valid: false, broken_at: cur.height, reason: 'chain_break' };
        }

        // 2) 해시 재계산 (h_{i-1} ∥ tx_hash ∥ block_hash ∥ height)
        const recomputed = bufToHex(await sha256(
          prev.local_hash + cur.tx_hash + cur.block_hash + String(cur.height)
        ));
        if (recomputed !== cur.local_hash) {
          return { valid: false, broken_at: cur.height, reason: 'hash_mismatch' };
        }
      }
      return { valid: true, broken_at: null };
    }

    /**
     * 로컬 재무 상태 직접 갱신 (초기화 또는 서버 동기화용)
     * @param {Object} newState  — { 'bs-cash': 숫자, ... }
     */
    async setFinancialState(newState) {
      const db = await openDB();
      await idbPut(db, IDB_FS_KEY, {
        state:     newState,
        updatedAt: new Date().toISOString(),
        block_hash: null,
      });
    }

    /* ──────────────────────────────────────────────
     *  정적 메서드: 지갑 생성 / 로드 / 삭제
     * ────────────────────────────────────────────── */

    /**
     * 새 지갑 생성 후 IndexedDB에 저장
     * @param {string} [passphrase='']  — 빈 문자열이면 기기 고유 entropy 사용
     * @returns {GopangWallet}
     */
    static async create(passphrase = '') {
      const kp  = await generateKeyPair();
      const enc = await encryptPrivKey(
        b64uToBuf(kp.privateKeyB64u).buffer,
        passphrase || await GopangWallet._deviceEntropy()
      );

      const record = {
        publicKeyB64u : kp.publicKeyB64u,
        publicKeyHex  : kp.publicKeyHex,
        encPrivKey    : bufToB64u(enc),   // AES-GCM 암호화된 개인키
        createdAt     : nowSec(),
      };

      const db = await openDB();
      await idbPut(db, IDB_KEY_ID, record);
      localStorage.setItem(LS_PUBKEY, kp.publicKeyB64u);

      return new GopangWallet({
        publicKey   : kp.publicKey,
        privateKey  : kp.privateKey,
        publicKeyB64u: kp.publicKeyB64u,
        publicKeyHex : kp.publicKeyHex,
        handle      : localStorage.getItem(LS_HANDLE),
        guid        : null,
      });
    }

    /**
     * 저장된 지갑 로드
     * @param {string} [passphrase='']
     * @returns {GopangWallet|null}  — 지갑 없으면 null
     */
    static async load(passphrase = '') {
      try {
        const db     = await openDB();
        const record = await idbGet(db, IDB_KEY_ID);
        if (!record) return null;

        const encBuf = b64uToBuf(record.encPrivKey).buffer;
        const privRaw = await decryptPrivKey(
          encBuf,
          passphrase || await GopangWallet._deviceEntropy()
        );

        // JWK 형식으로 복원
        const privJwk = {
          kty: 'OKP', crv: 'Ed25519',
          x  : record.publicKeyB64u,
          d  : bufToB64u(privRaw),
          key_ops: ['sign'],
        };
        const privKey = await crypto.subtle.importKey(
          'jwk', privJwk, { name: 'Ed25519' }, false, ['sign']
        );
        const pubRaw  = b64uToBuf(record.publicKeyB64u);
        const pubKey  = await crypto.subtle.importKey(
          'raw', pubRaw, { name: 'Ed25519' }, false, ['verify']
        );

        return new GopangWallet({
          publicKey    : pubKey,
          privateKey   : privKey,
          publicKeyB64u: record.publicKeyB64u,
          publicKeyHex : record.publicKeyHex,
          handle       : localStorage.getItem(LS_HANDLE),
          guid         : null,
        });
      } catch (e) {
        console.error('[GopangWallet] load 실패:', e);
        return null;
      }
    }

    /**
     * 지갑 존재 여부 확인 (복호화 없이)
     */
    static async exists() {
      try {
        const db = await openDB();
        const r  = await idbGet(db, IDB_KEY_ID);
        return !!r;
      } catch { return false; }
    }

    /**
     * 지갑 삭제 (초기화)
     */
    static async destroy() {
      const db = await openDB();
      await idbDel(db, IDB_KEY_ID);
      localStorage.removeItem(LS_PUBKEY);
      localStorage.removeItem(LS_HANDLE);
    }

    /**
     * 백업용 개인키 내보내기 (Base64URL)
     * 사용자가 직접 안전한 곳에 보관해야 함
     */
    async exportPrivateKey() {
      const jwk = await crypto.subtle.exportKey('jwk', this._privKey);
      return jwk.d; // Base64URL
    }

    /**
     * 백업에서 복원 (개인키 Base64URL + 공개키 Base64URL)
     */
    static async importFromBackup(privKeyB64u, pubKeyB64u, passphrase = '') {
      const privJwk = {
        kty: 'OKP', crv: 'Ed25519',
        x  : pubKeyB64u,
        d  : privKeyB64u,
        key_ops: ['sign'],
      };
      const privKey = await crypto.subtle.importKey(
        'jwk', privJwk, { name: 'Ed25519' }, true, ['sign']
      );
      const pubRaw  = b64uToBuf(pubKeyB64u);
      const pubKey  = await crypto.subtle.importKey(
        'raw', pubRaw, { name: 'Ed25519' }, false, ['verify']
      );
      const pubHex  = bufToHex(pubRaw);

      const enc = await encryptPrivKey(
        b64uToBuf(privKeyB64u).buffer,
        passphrase || await GopangWallet._deviceEntropy()
      );
      const record = {
        publicKeyB64u: pubKeyB64u,
        publicKeyHex : pubHex,
        encPrivKey   : bufToB64u(enc),
        createdAt    : nowSec(),
      };
      const db = await openDB();
      await idbPut(db, IDB_KEY_ID, record);
      localStorage.setItem(LS_PUBKEY, pubKeyB64u);

      return new GopangWallet({
        publicKey    : pubKey,
        privateKey   : privKey,
        publicKeyB64u: pubKeyB64u,
        publicKeyHex : pubHex,
        handle       : localStorage.getItem(LS_HANDLE),
        guid         : null,
      });
    }

    /* ── 내부: 기기 고유 entropy (passphrase 미사용 시 대체) ── */
    static async _deviceEntropy() {
      // UserAgent + 고정 salt → SHA-256 → hex
      // 동일 기기+브라우저면 동일값, 완벽한 보안이 아님
      // 프로덕션에서는 사용자 passphrase 권장
      const raw = navigator.userAgent + 'gopang-wallet-v1-entropy';
      const buf = await sha256(raw);
      return bufToHex(buf);
    }

    /* ── 정적 유틸 노출 ── */
    static nicknameHash(nickname, lang) { return nicknameHash(nickname, lang); }
    static verify(publicKeyB64u, payload, signatureB64u) {
      return verify(publicKeyB64u, payload, signatureB64u);
    }
    static bufToB64u(buf)     { return bufToB64u(buf); }
    static b64uToBuf(b64u)    { return b64uToBuf(b64u); }
    static bufToHex(buf)      { return bufToHex(buf); }
  }

  /* ────────────────────────────────────────────────
   *  TX 타입 상수 (전체 Gopang 공통)
   * ──────────────────────────────────────────────── */
  GopangWallet.TX = Object.freeze({
    USER_REGISTER      : 'USER_REGISTER',
    GDC_TRANSFER       : 'GDC_TRANSFER',
    BIZ_ORDER          : 'BIZ_ORDER',
    BIZ_ORDER_CANCEL   : 'BIZ_ORDER_CANCEL',
    BIZ_REVIEW         : 'BIZ_REVIEW',
    BIZ_PRODUCT_UPSERT : 'BIZ_PRODUCT_UPSERT',
    PDV_CONSENT        : 'PDV_CONSENT',
    PDV_REVOKE         : 'PDV_REVOKE',
  });

  GopangWallet.VERSION = VERSION;

  /* ────────────────────────────────────────────────
   *  정적 유틸 추가 노출 (v2.0)
   * ──────────────────────────────────────────────── */
  GopangWallet.sortedStringify       = sortedStringify;
  GopangWallet.computePrevSettleHash = computePrevSettleHash;
  GopangWallet.buildTxWithPrevHash   = buildTxWithPrevHash;
  GopangWallet.signTx                = signTx;
  GopangWallet.appendHashChain       = appendHashChain;

  /* ────────────────────────────────────────────────
   *  전역 노출
   * ──────────────────────────────────────────────── */
  global.GopangWallet = GopangWallet;

  // ESM 환경 대응
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = GopangWallet;
  }

  /* ────────────────────────────────────────────────
   *  window.gopangWallet 싱글턴 자동 초기화
   *  gopang-app.js에서 window.gopangWallet.sign() 등으로 접근
   *  지갑이 없으면 null — gopang-app.js _gwpSignExecute가 Phase 1 폴백 처리
   * ──────────────────────────────────────────────── */
  (async () => {
    try {
      let wallet = await GopangWallet.load();
      if (!wallet) {
        // 최초 실행 — 자동 생성 (passphrase 없이 기기 entropy 사용)
        wallet = await GopangWallet.create();
        console.info('[GopangWallet] 새 지갑 자동 생성 완료');
      }

      // gopang_user_v3에서 guid 연결
      const stored = (() => {
        try { return JSON.parse(localStorage.getItem('gopang_user_v3') || 'null'); }
        catch { return null; }
      })();
      if (stored?.ipv6) {
        wallet.setIdentity({ guid: stored.ipv6, handle: stored.handle || null });
      }

      // 로컬 재무 상태가 비어있으면 서버에서 초기 동기화 시도
      const fs = await wallet.getFinancialState();
      if (!fs || Object.keys(fs).length === 0) {
        if (stored?.ipv6) {
          try {
            const sbKey = localStorage.getItem('_sbkey')
                        || localStorage.getItem('gopang_supabase_key')
                        || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImViYmVjamZyd2Fzd2JkeWJiZ2l1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzk1NjE5ODQsImV4cCI6MjA5NTEzNzk4NH0.H2ahQKtWdSke04Pdi3hDY86pdTx7UUKPUpQMlS_zciA';
            const res = await fetch(
              `https://ebbecjfrwaswbdybbgiu.supabase.co/rest/v1/user_profiles`
              + `?current_ipv6=eq.${stored.ipv6}&select=extra&limit=1`,
              { headers: { apikey: sbKey, 'Authorization': `Bearer ${sbKey}` } }
            );
            if (res.ok) {
              const rows = await res.json();
              const serverFs = rows[0]?.extra?.fs;
              if (serverFs) {
                await wallet.setFinancialState(serverFs);
                console.info('[GopangWallet] 서버 재무 상태 초기 동기화 완료');
              }
            }
          } catch(e) {
            console.warn('[GopangWallet] 서버 동기화 실패 (무시):', e.message);
          }
        }
      }

      global.gopangWallet = wallet;
      console.info('[GopangWallet] 싱글턴 초기화 완료 | v' + VERSION
                   + ' | guid:', wallet.guid || '미연결');
    } catch(e) {
      console.error('[GopangWallet] 초기화 실패:', e.message);
      global.gopangWallet = null;
    }
  })();

})(typeof globalThis !== 'undefined' ? globalThis : window);

/* ====================================================
 * gopang-wallet.js v2.0 사용 예시 (주석)
 * ====================================================
 *
 * // ── 기본 사용 ──────────────────────────────────────
 *
 * // 1) 최초 지갑 생성 (또는 자동 — window.gopangWallet 싱글턴 참조)
 * const wallet = await GopangWallet.create();           // passphrase 없이
 * const wallet = await GopangWallet.create('비밀번호'); // passphrase 지정
 *
 * // 2) 기존 지갑 로드
 * const wallet = await GopangWallet.load();
 * if (!wallet) { // 지갑 없음 → create() }
 *
 * // 3) 신원 연결 (로그인 후)
 * wallet.setIdentity({ handle: '@보영반점#BOY1', guid: '2001:db8::1' });
 *
 * // ── v2.0: UTXO 서명 흐름 ───────────────────────────
 *
 * // 4) GWP_SIGN_REQUEST 수신 시 (gopang-app.js _gwpSignExecute 내부)
 * const signedTx = await window.gopangWallet.sign(rawTx);
 * // signedTx = { tx, tx_hash, buyer_sig, buyer_public_key, prev_settle_hash }
 *
 * // 5) 직접 UTXO tx 빌드 + 서명
 * const { tx, prevSettleHash } = await GopangWallet.buildTxWithPrevHash({
 *   buyerGuid:     '2001:db8::buyer',
 *   sellerGuid:    'pguid-BOYOUNG',
 *   total:         24000,
 *   sellerNet:     23280,
 *   platformFee:   720,
 *   financialState: { 'bs-cash': 100000, 'pl-purchase': 0 },
 *   items: [{ id:'menu-001', name:'짜장면', price:12000, quantity:2 }],
 * });
 * const { tx_hash, buyer_sig } = await GopangWallet.signTx(privateKey, tx);
 *
 * // ── v2.0: 잔액 · 재무 상태 ──────────────────────────
 *
 * // 6) 잔액 조회
 * const balance = await wallet.getBalance();   // bs-cash
 *
 * // 7) 재무 상태 전체 조회
 * const fs = await wallet.getFinancialState();
 * // { 'bs-cash': 76000, 'pl-purchase': 24000, ... }
 *
 * // 8) prev_settle_hash 계산
 * const { prevSettleHash } = await wallet.buildPrevSettleHash();
 *
 * // ── v2.0: 청구권 자기갱신 + Hash Chain ──────────────
 *
 * // 9) L1 청구권 수신 → 재무 상태 갱신 + Hash Chain 기록
 * await wallet.redeemClaim({
 *   block_hash: 'abc123...',
 *   block_id:   'pb-block-id',
 *   tx_hash:    'def456...',
 *   claims: [
 *     { direction:'debit', amount:24000, fs_account:'pl-purchase',
 *       expires_at:'2026-06-13T00:00:00Z' },
 *   ],
 * });
 *
 * // 10) Hash Chain 조회 및 검증
 * const chain  = await wallet.getHashChain();
 * const result = await wallet.verifyChain();
 * // result = { valid: true, broken_at: null }
 *
 * // ── 기타 ────────────────────────────────────────────
 *
 * // 11) nickname_hash 생성
 * const hash = await GopangWallet.nicknameHash('보영반점');
 *
 * // 12) 개인키 백업 / 복원
 * const privB64u = await wallet.exportPrivateKey();
 * const restored = await GopangWallet.importFromBackup(privB64u, wallet.publicKeyB64u);
 *
 * // 13) 서명 검증
 * const ok = await GopangWallet.verify(pubKeyB64u, payload, sig);
 *
 * ==================================================== */
