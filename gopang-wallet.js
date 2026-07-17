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
  const IDB_VER          = 3;               // v3.0: hash_chain → anchor_chain (OpenHash 통합)
  const IDB_STORE        = 'keys';           // 개인키·재무상태 저장
  const IDB_STORE_CHAIN  = 'anchor_chain';   // OpenHash 통합 앵커 체인 (v3.0)
  const IDB_KEY_ID       = 'ed25519-main';
  const IDB_X25519_ID    = 'x25519-enc-main';  // 암호화 전용 키페어 (Ed25519와 별도)
  const IDB_FS_KEY       = 'financial_state'; // 로컬 재무제표 키
  const LS_PUBKEY        = 'gopang_wallet_pubkey';
  const LS_X25519_PUBKEY = 'gopang_wallet_x25519_pubkey';
  const LS_HANDLE        = 'gopang_wallet_handle';
  const LS_WEBAUTHN_CRED = 'gopang_wallet_webauthn_cred_id';
  const WEBAUTHN_RP_ID   = 'hondi.net';  // 전체 hondi.net 서브도메인에서 credential 공유
  // PRF는 결정론적 — 동일 salt + 동일 authenticator = 항상 동일 32바이트.
  // 서버에 아무것도 저장할 필요 없음.
  const WEBAUTHN_PRF_SALT = new TextEncoder().encode('gopang-wallet-v1-prf-salt');
  const WORKER_URL       = 'https://hondi-proxy.tensor-city.workers.dev';

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
        // v2: hash_chain store (구버전 — v3에서 교체)
        if (oldVer < 2) db.createObjectStore('hash_chain', { keyPath: 'height' });
        // v3: anchor_chain (OpenHash 통합 — keyPath: entryHash)
        if (oldVer < 3) {
          if (db.objectStoreNames.contains('hash_chain')) db.deleteObjectStore('hash_chain');
          db.createObjectStore(IDB_STORE_CHAIN, { keyPath: 'entryHash' });
        }
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
      const tx    = db.transaction(IDB_STORE_CHAIN, 'readonly');
      const store = tx.objectStore(IDB_STORE_CHAIN);
      // keyPath='entryHash' → getAll 후 recorded_at 기준 최신 조회
      const req   = store.getAll();
      req.onsuccess = e => {
        const all = e.target.result || [];
        if (!all.length) { resolve(null); return; }
        all.sort((a, b) => new Date(b.recorded_at) - new Date(a.recorded_at));
        resolve(all[0]);
      };
      req.onerror = e => reject(e.target.error);
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
   *  X25519 암호화 전용 키페어 (Ed25519와 별도)
   *  용도: PC가 입력한 민감정보(API Key 등)를 이 공개키로
   *        봉투 암호화 → Supabase에는 암호문만 저장
   *        복호화는 이 키페어를 보관한 기기(휴대폰)에서만 가능
   * ──────────────────────────────────────────────── */

  /**
   * 새 X25519 키페어 생성 (암호화 전용 — 서명 불가)
   * @returns {{ publicKey, privateKey, publicKeyB64u, privateKeyB64u }}
   */
  async function generateX25519KeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const pubRaw  = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

    return {
      publicKey     : keyPair.publicKey,
      privateKey    : keyPair.privateKey,
      publicKeyB64u : bufToB64u(pubRaw),
      privateKeyB64u: privJwk.d,
    };
  }

  /**
   * ECDH(X25519) 공유키 유도 → AES-GCM 256 CryptoKey
   * @param {CryptoKey} privateKey  — 내 X25519 개인키
   * @param {CryptoKey} peerPublicKey — 상대 X25519 공개키
   */
  async function _deriveSharedAesKey(privateKey, peerPublicKey) {
    return crypto.subtle.deriveKey(
      { name: 'X25519', public: peerPublicKey },
      privateKey,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
  }

  /**
   * 봉투 암호화 — PC가 휴대폰의 X25519 공개키로 평문을 암호화
   * 송신자(PC)는 매번 임시(ephemeral) 키페어를 새로 생성하므로
   * 송신자 쪽에 개인키를 보관할 필요가 없음 (PC는 거울일 뿐)
   *
   * @param {string} recipientPubKeyB64u — 수신자(휴대폰)의 X25519 공개키
   * @param {string} plaintext
   * @returns {{ ephemeralPubKey, iv, ciphertext }} 전부 Base64URL
   */
  async function sealForRecipient(recipientPubKeyB64u, plaintext) {
    const recipientPubKey = await crypto.subtle.importKey(
      'raw', b64uToBuf(recipientPubKeyB64u),
      { name: 'X25519' }, false, []
    );

    // 송신자(PC) 측 1회용 임시 키페어 — PC에는 절대 저장하지 않음
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'X25519' }, true, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'X25519', public: recipientPubKey },
      ephemeral.privateKey,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt']
    );

    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey,
      new TextEncoder().encode(plaintext)
    );
    const ephemeralPubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);

    return {
      ephemeralPubKey: bufToB64u(ephemeralPubRaw),
      iv             : bufToB64u(iv),
      ciphertext     : bufToB64u(enc),
    };
  }

  /**
   * 봉투 복호화 — 휴대폰이 자신의 X25519 개인키로 PC가 보낸 암호문을 해독
   * @param {CryptoKey} myPrivateKey
   * @param {{ ephemeralPubKey, iv, ciphertext }} sealed
   * @returns {string} plaintext
   */
  async function openSealed(myPrivateKey, sealed) {
    const ephemeralPubKey = await crypto.subtle.importKey(
      'raw', b64uToBuf(sealed.ephemeralPubKey),
      { name: 'X25519' }, false, []
    );
    const aesKey = await _deriveSharedAesKey(myPrivateKey, ephemeralPubKey);
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64uToBuf(sealed.iv) },
      aesKey, b64uToBuf(sealed.ciphertext)
    );
    return new TextDecoder().decode(dec);
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
    // ── v3.0: OpenHash anchor() 위임 (단일 체인 통합) ──────────────────
    // hashChain.js의 anchor()를 통해 단일 앵커 체인에 기록
    // contentHash = SHA-256(txHash + blockHash) — 거래 식별자
    // signatures  = [] → guid fallback (wallet 컨텍스트에서 서명)
    try {
      const { anchor } = await import('./src/openhash/hashChain.js');
      const contentInput = txHash + (blockHash || '');
      const buf         = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(contentInput));
      const contentHash = bufToHex(buf);

      // wallet 서명 (this 컨텍스트 없으므로 window.gopangWallet 사용)
      let sig = contentHash;  // fallback
      try {
        if (window.gopangWallet?._privKey) {
          const sigBuf = await crypto.subtle.sign('Ed25519', window.gopangWallet._privKey, new TextEncoder().encode(contentHash));
          sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
        }
      } catch(e) { /* fallback 유지 */ }

      const result = await anchor(contentHash, [sig], pdvSessionId || txHash);

      // anchor_chain store에 저장 (OpenHash 통합 레코드)
      const record = {
        entryHash:     result.entryHash,
        contentHash,
        prevHash:      result.prevHash,
        tx_hash:       txHash,
        block_hash:    blockHash,
        block_id:      blockId,
        layer:         result.layer,
        recorded_at:   new Date().toISOString(),
        pdv_session_id: pdvSessionId,
        pdv_type:      pdvType,
      };
      await idbChainPut(db, record);
      return record;
    } catch(e) {
      console.warn('[Wallet] appendHashChain anchor() 실패, 로컬 기록만:', e.message);
      // fallback: anchor() 실패 시 로컬만 기록
      const contentInput = txHash + (blockHash || '');
      const buf         = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(contentInput));
      const contentHash = bufToHex(buf);
      const record = {
        entryHash:     contentHash,
        contentHash,
        prevHash:      '0'.repeat(64),
        tx_hash:       txHash,
        block_hash:    blockHash,
        block_id:      blockId,
        layer:         'local',
        recorded_at:   new Date().toISOString(),
        pdv_session_id: pdvSessionId,
        pdv_type:      pdvType,
      };
      await idbChainPut(db, record);
      return record;
    }
  }

  /* ────────────────────────────────────────────────
   *  GopangWallet 클래스
   * ──────────────────────────────────────────────── */

  class GopangWallet {

    constructor({ publicKey, privateKey, publicKeyB64u, publicKeyHex, handle, guid, x25519PublicKey, x25519PrivateKey, x25519PublicKeyB64u }) {
      this._pubKey     = publicKey;
      this._privKey    = privateKey;
      this.publicKeyB64u = publicKeyB64u;
      this.publicKeyHex  = publicKeyHex;
      this.handle      = handle ?? null;   // @닉네임#태그
      this.guid        = guid   ?? null;   // user_profiles.current_ipv6
      // X25519 암호화 전용 키페어 (Ed25519와 별도 — PC→휴대폰 봉투암호화 수신용)
      this._x25519PrivKey   = x25519PrivateKey ?? null;
      this._x25519PubKey    = x25519PublicKey  ?? null;
      this.x25519PublicKeyB64u = x25519PublicKeyB64u ?? null;
    }

    /* ── 서명 (단순 문자열/바이트 페이로드 — TX 빌드와 무관) ── */
    async signPayload(payload) {
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

    /* ── X25519: 이 지갑(휴대폰)이 PC로부터 받은 봉투를 해독 ── */
    async openSealed(sealed) {
      if (!this._x25519PrivKey)
        throw new Error('wallet: X25519 키페어가 아직 등록되지 않았습니다. ensureX25519Key()를 먼저 호출하세요.');
      return openSealed(this._x25519PrivKey, sealed);
    }

    /* ── X25519 공개키 보유 여부 ── */
    hasX25519Key() {
      return !!this._x25519PubKey;
    }

    /* ── handle / guid 설정 ── */
    setIdentity({ handle, guid }) {
      if (handle) {
        this.handle = handle;
        localStorage.setItem(LS_HANDLE, handle);
      }
      if (guid) this.guid = guid;
    }

    // (2026-07-15 삭제 — registerPublicKey. Supabase user_profiles에
    //  직접 PATCH하던 옛날 방식이고, 지금은 handleProfilePost/
    //  _l1UpsertProfile(L1 기반)이 공개키 등록을 대신한다. gopang·gdc
    //  두 저장소 어디서도 이 메서드를 호출하는 곳이 없었다 — Supabase
    //  완전 폐기의 마지막 잔재라 정리한다.)

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
        // 2026-07-07 수정(실제 이중 계상 버그): 이 필터가 없었다 — GWP_DONE
        // 메시지에는 buyer_claim/seller_claim이 함께 실려 오는데(profile.html
        // _submitOrder 참고), 그동안 이 함수가 claimant 확인 없이 배열의
        // 모든 claim을 그대로 적용해서, 구매자의 로컬 재무제표에 판매자
        // 몫(seller_claim)까지 잘못 반영되고 있었다. claimant가 없는 옛날
        // claim(하위호환)은 그대로 허용한다.
        if (claim.claimant && this.guid && claim.claimant !== this.guid) {
          console.warn('[Wallet] 내 claim 아님, 건너뜀:', claim.claimant?.slice(0, 20));
          continue;
        }
        if (claim.expires_at && new Date(claim.expires_at).getTime() < now) {
          console.warn('[Wallet] 만료된 청구권 무시:', claim);
          continue;
        }
        const acc = claim.fs_account || 'bs-cash';
        const cur = parseFloat(fs[acc] ?? '0') || 0;
        // 2026-07-13 신설 — pl-cogs(매출원가)는 실제 현금 흐름이 아니라,
        // 이미 매입 시점(pl-purchase)에 지출된 현금을 사후적으로 매출과
        // 대응시키는 정보성 재분류일 뿐이다. bs-cash를 또 건드리면 같은
        // 지출을 두 번 차감하는 이중계상이 된다 — 반드시 제외해야 한다.
        const NON_CASH_ACCOUNTS = new Set(['pl-cogs']);
        if (claim.direction === 'credit') {
          fs[acc] = cur + (claim.amount || 0);
        } else if (claim.direction === 'debit') {
          // pl-purchase·pl-cogs: 누적 비용(양수) — cur + amount
          // bs-cash: 잔액 감소 — 별도 처리
          if (acc === 'pl-purchase' || acc === 'pl-cogs') {
            fs[acc] = cur + (claim.amount || 0);
          } else {
            fs[acc] = cur - (claim.amount || 0);
          }
        }
        // bs-cash 동기화 (pl 계정 변동 시) — 비현금 계정은 제외
        if (acc !== 'bs-cash' && !NON_CASH_ACCOUNTS.has(acc)) {
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
     * 2026-07-07 신설 — 재대사(reconcile). 로컬 IndexedDB(financial_state)가
     * 서버(L1) 실제 원장과 어긋났을 때(새 기기, 스토리지 초기화, 앱 재설치
     * 등) 서버 값으로 교정한다. 지금까지는 이 복구 경로가 아예 없었다 —
     * 로컬이 틀리면 영영 못 고치고, prev_settle_hash도 계속 틀려서 다음
     * 거래가 STALE_STATE로 막혔다.
     *
     * bs-cash(실잔액)와 block_hash(다음 prev_settle_hash 기준)만 서버 값
     *으로 덮어쓴다 — pl-purchase/pl-revenue(누적 통계)는 서버가 더 이상
     * 추적하지 않으므로(2026-07-07 L1 이관 이후) 로컬 이력을 그대로 둔다.
     *
     * 호출 시점 권장: 앱/지갑 초기화 직후(로그인 직후), 그리고 STALE_STATE
     * 오류를 받았을 때 재시도 전.
     *
     * @returns {{ drift: boolean, localBalance: number, serverBalance: number, blockHash: string|null }}
     */
    async hydrateFromServer() {
      if (!this.guid) throw new Error('[Wallet] guid(IPv6)가 설정되지 않았습니다.');

      const res  = await fetch(`${WORKER_URL}/biz/balance?guid=${encodeURIComponent(this.guid)}`);
      const data = await res.json().catch(() => null);
      if (!data?.ok) {
        throw new Error('[Wallet] 서버 잔액 조회 실패: ' + (data?.error || res.status));
      }

      const db  = await openDB();
      const rec = await idbGet(db, IDB_FS_KEY);
      const localFs = rec?.state || {};
      const localBsCash = parseFloat(localFs['bs-cash'] ?? '0') || 0;

      const drift = Math.abs(localBsCash - data.balance) > 0.01;
      if (drift) {
        console.warn('[Wallet] 로컬-서버 잔액 불일치 감지 — 서버 값으로 교정',
          '| local:', localBsCash, '| server:', data.balance);
      }

      const newFs = { ...localFs, 'bs-cash': data.balance };
      await idbPut(db, IDB_FS_KEY, {
        state:     newFs,
        updatedAt: new Date().toISOString(),
        // latest_block_hash가 없으면(지불 이력 없음) 기존 값 유지 —
        // main.pb.js 3단계는 prev_settle_hash:null을 "첫 거래"로 처리한다.
        block_hash: data.latest_block_hash || rec?.block_hash || null,
      });

      console.info('[Wallet] hydrateFromServer 완료',
        '| drift:', drift, '| balance:', data.balance);

      return {
        drift,
        localBalance:  localBsCash,
        serverBalance: data.balance,
        blockHash:     data.latest_block_hash || null,
      };
    }

    /**
     * Hash Chain 전체 조회
     * @returns {Array} chain 이력 배열 (height 오름차순)
     */
    async getHashChain() {
      const db = await openDB();
      const records = await idbChainGetAll(db);
      return records.sort((a, b) => new Date(a.recorded_at) - new Date(b.recorded_at));
    }

    /**
     * Hash Chain 연속성 검증
     * @returns {{ valid: boolean, broken_at: number|null }}
     */
    async verifyChain() {
      // v3.0: OpenHash anchor_chain — hashChain.js verifyChainIntegrity() 위임
      try {
        const { verifyChainIntegrity } = await import('./src/openhash/hashChain.js');
        return await verifyChainIntegrity();
      } catch(e) {
        console.warn('[Wallet] verifyChain 실패:', e.message);
        return { valid: false, broken_at: null, reason: e.message };
      }
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
        passphrase || await GopangWallet._webauthnEntropy()
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
          passphrase || await GopangWallet._webauthnEntropy()
        );

        // JWK 형식으로 복원
        // v6.0: extractable을 true로 — exportPrivateKey()(백업 키 내보내기)가
        // 첫 생성 직후뿐 아니라 재방문 세션(load() 경로)에서도 동작해야 한다.
        // 개인키 자체는 여전히 IndexedDB에 AES-GCM 암호화되어 있으므로, 이 변경이
        // 새로 노출시키는 것은 "이미 메모리에 로드된 이 세션의 키"뿐이다.
        const privJwk = {
          kty: 'OKP', crv: 'Ed25519',
          x  : record.publicKeyB64u,
          d  : bufToB64u(privRaw),
          key_ops: ['sign'],
        };
        const privKey = await crypto.subtle.importKey(
          'jwk', privJwk, { name: 'Ed25519' }, true, ['sign']
        );
        const pubRaw  = b64uToBuf(record.publicKeyB64u);
        const pubKey  = await crypto.subtle.importKey(
          'raw', pubRaw, { name: 'Ed25519' }, false, ['verify']
        );

        // X25519 암호화 키페어 — 없으면 null (ensureX25519Key()로 추후 생성)
        let x25519PrivKey = null, x25519PubKey = null, x25519PubKeyB64u = null;
        const xRecord = await idbGet(db, IDB_X25519_ID).catch(() => null);
        if (xRecord) {
          const xEncBuf = b64uToBuf(xRecord.encPrivKey).buffer;
          const xPrivRaw = await decryptPrivKey(
            xEncBuf,
            passphrase || await GopangWallet._webauthnEntropy()
          );
          const xPrivJwk = {
            kty: 'OKP', crv: 'X25519',
            x  : xRecord.publicKeyB64u,
            d  : bufToB64u(xPrivRaw),
            key_ops: ['deriveKey', 'deriveBits'],
          };
          x25519PrivKey = await crypto.subtle.importKey(
            'jwk', xPrivJwk, { name: 'X25519' }, false, ['deriveKey']
          );
          x25519PubKey = await crypto.subtle.importKey(
            'raw', b64uToBuf(xRecord.publicKeyB64u), { name: 'X25519' }, false, []
          );
          x25519PubKeyB64u = xRecord.publicKeyB64u;
        }

        return new GopangWallet({
          publicKey    : pubKey,
          privateKey   : privKey,
          publicKeyB64u: record.publicKeyB64u,
          publicKeyHex : record.publicKeyHex,
          handle       : localStorage.getItem(LS_HANDLE),
          guid         : null,
          x25519PrivateKey   : x25519PrivKey,
          x25519PublicKey    : x25519PubKey,
          x25519PublicKeyB64u: x25519PubKeyB64u,
        });
      } catch (e) {
        console.error('[GopangWallet] load 실패:', e);
        return null;
      }
    }

    /**
     * X25519 암호화 키페어 보장 — 없으면 생성 후 IndexedDB에 저장
     * "공장 초기화 후 첫 접속 시 자동 개시"용 진입점
     * 휴대폰(설정 창)에서만 호출할 것 — PC는 이 키를 생성하지 않음
     * @param {string} [passphrase='']
     * @returns {{ publicKeyB64u }} 등록할 공개키
     */
    async ensureX25519Key(passphrase = '') {
      if (this._x25519PrivKey && this.x25519PublicKeyB64u) {
        return { publicKeyB64u: this.x25519PublicKeyB64u, created: false };
      }

      const kp  = await generateX25519KeyPair();
      const enc = await encryptPrivKey(
        b64uToBuf(kp.privateKeyB64u).buffer,
        passphrase || await GopangWallet._webauthnEntropy()
      );

      const record = {
        publicKeyB64u: kp.publicKeyB64u,
        encPrivKey   : bufToB64u(enc),
        createdAt    : nowSec(),
      };
      const db = await openDB();
      await idbPut(db, IDB_X25519_ID, record);
      localStorage.setItem(LS_X25519_PUBKEY, kp.publicKeyB64u);

      this._x25519PrivKey      = kp.privateKey;
      this._x25519PubKey       = kp.publicKey;
      this.x25519PublicKeyB64u = kp.publicKeyB64u;

      return { publicKeyB64u: kp.publicKeyB64u, created: true };
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
      await idbDel(db, IDB_X25519_ID).catch(() => {});
      localStorage.removeItem(LS_PUBKEY);
      localStorage.removeItem(LS_X25519_PUBKEY);
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
        passphrase || await GopangWallet._webauthnEntropy()
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

    /**
     * v6.0 — 백업 키 복구: 개인키(Base64URL) 한 줄만으로 지갑 전체 복원.
     * 공개키는 별도로 저장/입력받지 않고 개인키로부터 결정적으로 유도한다.
     *
     * 원리: Ed25519 개인키는 32바이트 시드 그 자체이며(JWK의 `d` 값과 동일),
     * PKCS8 DER 포맷은 Ed25519에 한해 알고리즘 파라미터가 없어 앞 16바이트
     * 헤더가 항상 고정값이다 — `302e020100300506032b657004220420`(hex).
     * 이 고정 헤더 + 32바이트 시드로 PKCS8 버퍼를 직접 구성해 importKey하면,
     * WebCrypto 구현이 공개키를 내부적으로 계산해 jwk export 시 `x`로 돌려준다
     * (실제 브라우저/Node WebCrypto에서 라운드트립 서명·검증으로 검증된 방식).
     *
     * "백업 키를 다시 입력하면 정확히 같은 계정이 복원된다"가 보장되는 이유는
     * 이 유도가 결정적(deterministic)이기 때문 — 같은 32바이트는 항상 같은
     * 공개키(=같은 guid 검증 결과)를 낸다.
     *
     * @param {string} privKeyB64u — exportPrivateKey()가 내보낸 그 문자열
     * @param {string} [passphrase='']
     * @returns {GopangWallet}
     * @throws {Error} 형식이 32바이트가 아니면 (잘못 붙여넣은 경우)
     */
    static async restoreFromPrivateKey(privKeyB64u, passphrase = '') {
      const seed = b64uToBuf(privKeyB64u.trim());
      if (seed.length !== 32) {
        throw new Error('백업 키 형식이 올바르지 않습니다 (32바이트가 아님).');
      }
      const PKCS8_ED25519_HEADER = Uint8Array.from(
        '302e020100300506032b657004220420'.match(/.{2}/g).map(h => parseInt(h, 16))
      );
      const pkcs8 = new Uint8Array(PKCS8_ED25519_HEADER.length + seed.length);
      pkcs8.set(PKCS8_ED25519_HEADER, 0);
      pkcs8.set(seed, PKCS8_ED25519_HEADER.length);

      let imported;
      try {
        imported = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
      } catch (e) {
        throw new Error('백업 키를 읽을 수 없습니다: ' + e.message);
      }
      const jwk = await crypto.subtle.exportKey('jwk', imported);
      const pubKeyB64u = jwk.x; // 결정적으로 유도된 공개키

      return GopangWallet.importFromBackup(privKeyB64u.trim(), pubKeyB64u, passphrase);
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

    /* ── WebAuthn PRF 기반 entropy ──────────────────────────
     * enroll 안 됐으면 기존 _deviceEntropy()로 그대로 폴백 (하위호환).
     * enroll 됐는데 생체인증 실패/취소 시엔 여기서 예외가 나며,
     * 이는 decryptPrivKey()에서 AES-GCM auth tag 불일치로 안전하게 실패한다
     * (평문 노출 없이 load() 쪽 catch로 흡수됨).
     * ──────────────────────────────────────────────────── */
    static async _webauthnEntropy() {
      const credIdB64u = localStorage.getItem(LS_WEBAUTHN_CRED);
      if (!credIdB64u) return GopangWallet._deviceEntropy();

      const prfBytes = await GopangWallet._prfEval(b64uToBuf(credIdB64u).buffer);
      return bufToHex(prfBytes.buffer);
    }

    /** 등록된 credential로 PRF 값을 재도출 (매번 동일 salt → 동일 결과) */
    static async _prfEval(credentialIdBuf) {
      const assertion = await navigator.credentials.get({
        publicKey: {
          rpId: WEBAUTHN_RP_ID,
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{ id: credentialIdBuf, type: 'public-key' }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: WEBAUTHN_PRF_SALT } } },
        },
      });
      const results = assertion.getClientExtensionResults();
      const first = results && results.prf && results.prf.results && results.prf.results.first;
      if (!first) throw new Error('WEBAUTHN_PRF_EVAL_FAILED');
      return new Uint8Array(first);
    }

    /**
     * 플랫폼 인증기(지문/얼굴)를 새로 등록하고, 현재 지갑의 개인키를
     * _deviceEntropy() 암호화 → PRF entropy 암호화로 전환한다.
     * @returns {{ ok: boolean, reason?: string }}
     *   reason 'PRF_UNSUPPORTED' — 이 브라우저/인증기는 PRF 미지원 → 폴백 유지, UI에서 안내할 것
     *   reason 'NO_WALLET' — 아직 지갑이 없음 (create() 먼저 호출)
     */
    static async enrollWebAuthn() {
      if (!window.PublicKeyCredential) return { ok: false, reason: 'PRF_UNSUPPORTED' };

      const db = await openDB();
      const record = await idbGet(db, IDB_KEY_ID);
      if (!record) return { ok: false, reason: 'NO_WALLET' };

      const cred = await navigator.credentials.create({
        publicKey: {
          rp: { id: WEBAUTHN_RP_ID, name: 'Hondi Wallet' },
          user: {
            id: b64uToBuf(record.publicKeyB64u),
            name: localStorage.getItem(LS_HANDLE) || 'gopang-wallet',
            displayName: 'Gopang Wallet',
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required',
          },
          extensions: { prf: {} },
        },
      });

      const prfEnabled = cred.getClientExtensionResults() && cred.getClientExtensionResults().prf
        && cred.getClientExtensionResults().prf.enabled;
      if (!prfEnabled) return { ok: false, reason: 'PRF_UNSUPPORTED' };

      // 기존 device-entropy로 복호화 → 새 PRF-entropy로 재암호화 (Ed25519 + X25519 둘 다)
      const oldEntropy = await GopangWallet._deviceEntropy();
      const newEntropyBytes = await GopangWallet._prfEval(cred.rawId);
      const newEntropy = bufToHex(newEntropyBytes.buffer);

      const privRaw = await decryptPrivKey(b64uToBuf(record.encPrivKey).buffer, oldEntropy);
      const reEnc = await encryptPrivKey(privRaw, newEntropy);
      await idbPut(db, IDB_KEY_ID, { ...record, encPrivKey: bufToB64u(reEnc) });

      const xRecord = await idbGet(db, IDB_X25519_ID).catch(() => null);
      if (xRecord) {
        const xPrivRaw = await decryptPrivKey(b64uToBuf(xRecord.encPrivKey).buffer, oldEntropy);
        const xReEnc = await encryptPrivKey(xPrivRaw, newEntropy);
        await idbPut(db, IDB_X25519_ID, { ...xRecord, encPrivKey: bufToB64u(xReEnc) });
      }

      localStorage.setItem(LS_WEBAUTHN_CRED, bufToB64u(cred.rawId));
      return { ok: true };
    }

    static isWebAuthnEnrolled() {
      return !!localStorage.getItem(LS_WEBAUTHN_CRED);
    }

    /**
     * WebAuthn 잠금 해제 — 다시 device-entropy 암호화로 되돌린다.
     * (기기 분실이 아니라 '지문 인식기가 자꾸 실패한다' 류의 사용자 요청 대응용)
     */
    static async disableWebAuthn() {
      if (!GopangWallet.isWebAuthnEnrolled()) return { ok: true, already: true };

      const db = await openDB();
      const record = await idbGet(db, IDB_KEY_ID);
      if (!record) return { ok: false, reason: 'NO_WALLET' };

      const credIdB64u = localStorage.getItem(LS_WEBAUTHN_CRED);
      const oldEntropyBytes = await GopangWallet._prfEval(b64uToBuf(credIdB64u).buffer);
      const oldEntropy = bufToHex(oldEntropyBytes.buffer);
      const newEntropy = await GopangWallet._deviceEntropy();

      const privRaw = await decryptPrivKey(b64uToBuf(record.encPrivKey).buffer, oldEntropy);
      const reEnc = await encryptPrivKey(privRaw, newEntropy);
      await idbPut(db, IDB_KEY_ID, { ...record, encPrivKey: bufToB64u(reEnc) });

      const xRecord = await idbGet(db, IDB_X25519_ID).catch(() => null);
      if (xRecord) {
        const xPrivRaw = await decryptPrivKey(b64uToBuf(xRecord.encPrivKey).buffer, oldEntropy);
        const xReEnc = await encryptPrivKey(xPrivRaw, newEntropy);
        await idbPut(db, IDB_X25519_ID, { ...xRecord, encPrivKey: bufToB64u(xReEnc) });
      }

      localStorage.removeItem(LS_WEBAUTHN_CRED);
      return { ok: true };
    }

    /* ── 정적 유틸 노출 ── */
    static nicknameHash(nickname, lang) { return nicknameHash(nickname, lang); }
    static verify(publicKeyB64u, payload, signatureB64u) {
      return verify(publicKeyB64u, payload, signatureB64u);
    }
    /**
     * PC(거울)에서 호출 — 지갑 인스턴스 없이, 휴대폰의 X25519 공개키만으로 봉투 암호화
     * @param {string} recipientPubKeyB64u — 휴대폰의 X25519 공개키
     * @param {string} plaintext
     */
    static async sealForRecipient(recipientPubKeyB64u, plaintext) {
      return sealForRecipient(recipientPubKeyB64u, plaintext);
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

      // gopang_user_v4에서 guid 연결
      const stored = (() => {
        try { return JSON.parse(localStorage.getItem('gopang_user_v4') || 'null'); }
        catch { return null; }
      })();
      if (stored?.ipv6) {
        wallet.setIdentity({ guid: stored.ipv6, handle: stored.handle || null });
      }

      // 2026-07-07 재수정: "fs가 비어있으면 동기화"였던 조건을 없앤다.
      // 오늘 가입 시점에 fs를 명시적으로 {bs-cash:0,...}로 초기화하도록
      // 바꿨는데(_initGdcWalletAndFs), 그 결과 fs가 가입 직후부터 절대
      // "비어있지" 않게 돼서 — 이 hydrateFromServer() 호출이 가입 이후
      // 평생 단 한 번도 다시 실행되지 않는 상태가 됐다(사고실험으로 발견).
      // 판매자처럼 거래에 실시간으로 참여하지 않는 기기는 이게 사실상
      // 유일한 재대사 경로인데, 그게 막혀 있었다는 뜻이다. 이제 guid가
      // 있으면 매 앱 실행마다 무조건 서버 값으로 재대사한다 — 실패해도
      // (오프라인 등) 로컬 값을 그대로 쓰면 되므로 앱 시작을 막지 않는다.
      if (stored?.ipv6) {
        try {
          await wallet.hydrateFromServer();
        } catch(e) {
          console.warn('[GopangWallet] 서버 동기화 실패 (무시):', e.message);
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


