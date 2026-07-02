-- ================================================================
-- gduda_readiness.sql
-- GDUDA 전환 준비 — users.hondi.net Phase 1 사전 작업
-- Supabase SQL Editor에 그대로 붙여넣기용
--
-- 기존 테이블 수정 원칙:
--   ADD COLUMN IF NOT EXISTS 만 사용 (기존 컬럼·데이터 보존)
--   기존 RPC search_entities() 는 새 파라미터 추가만 (하위 호환)
--
-- 실행 순서:
--   SECTION 1: 기존 테이블 컬럼 추가 (user_profiles, users)
--   SECTION 2: 신규 테이블 4개
--   SECTION 3: 인덱스
--   SECTION 4: search_entities() RPC 갱신 (하위 호환)
--   SECTION 5: 초기 데이터
--   SECTION 6: RLS 정책
-- ================================================================


-- ================================================================
-- SECTION 1: 기존 테이블 컬럼 추가
-- ================================================================

-- ── 1-A. user_profiles — GDUDA 식별자 컬럼 추가 ────────────────
-- primary_guid : SHA-256(공개키)[:32] — 영구 불변 정체성 (§2.1)
-- current_ipv6 : SHA-256(기기 핑거프린트) → IPv6 — 통신 주소
-- l1_node      : GDUDA L1 노드 ID (읍면동 수준)
-- l2_node      : GDUDA L2 노드 ID (시군구 수준)
-- l3_node      : GDUDA L3 노드 ID (광역시도 수준)
-- public_key   : ECDSA P-256 공개키 (base64) — primary_guid 생성 원본
-- registered_l1: 최초 등록 시 L1 노드 (이주 후에도 유지)

ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS primary_guid   text,
  ADD COLUMN IF NOT EXISTS current_ipv6   text,
  ADD COLUMN IF NOT EXISTS l1_node        text,
  ADD COLUMN IF NOT EXISTS l2_node        text,
  ADD COLUMN IF NOT EXISTS l3_node        text,
  ADD COLUMN IF NOT EXISTS public_key     text,
  ADD COLUMN IF NOT EXISTS registered_l1  text;

COMMENT ON COLUMN user_profiles.primary_guid
  IS 'GDUDA Primary GUID: pguid- + SHA-256(ECDSA 공개키)[:32]. 영구 불변.';
COMMENT ON COLUMN user_profiles.current_ipv6
  IS 'GDUDA Current IPv6: 기기 핑거프린트 기반 통신 주소. 기기 변경 시 갱신.';
COMMENT ON COLUMN user_profiles.l1_node
  IS 'GDUDA L1 노드 ID (읍면동). 예) KR-JEJU-JEJU-HANLIM';
COMMENT ON COLUMN user_profiles.l2_node
  IS 'GDUDA L2 노드 ID (시군구). 예) KR-JEJU-JEJU';
COMMENT ON COLUMN user_profiles.l3_node
  IS 'GDUDA L3 노드 ID (광역). 예) KR-JEJU';
COMMENT ON COLUMN user_profiles.public_key
  IS 'ECDSA P-256 공개키 (base64). primary_guid 재생성 및 서명 검증용.';
COMMENT ON COLUMN user_profiles.registered_l1
  IS '최초 등록 L1 노드. 이주 후 l1_node가 바뀌어도 등록 이력 보존.';


-- ── 1-B. users — GDUDA 전파 추적 컬럼 추가 ─────────────────────
-- gduda_registered : OpenHash 네트워크에 등록 완료 여부
-- gduda_registered_at : OpenHash 등록 완료 시각
-- l1_propagated_at : L1→L2 전파 완료 시각
-- l2_propagated_at : L2→L3 배치 동기화 완료 시각 (10분 배치)
-- l3_propagated_at : L3→L4 배치 동기화 완료 시각 (1시간 배치)

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS gduda_registered    boolean     DEFAULT false,
  ADD COLUMN IF NOT EXISTS gduda_registered_at timestamptz,
  ADD COLUMN IF NOT EXISTS l1_propagated_at    timestamptz,
  ADD COLUMN IF NOT EXISTS l2_propagated_at    timestamptz,
  ADD COLUMN IF NOT EXISTS l3_propagated_at    timestamptz;

COMMENT ON COLUMN users.gduda_registered
  IS 'OpenHash 네트워크 등록 완료 여부. Phase 2 이후 활성화.';
COMMENT ON COLUMN users.l1_propagated_at
  IS 'L1→L2 즉시 전파 완료 시각. NULL이면 미전파.';
COMMENT ON COLUMN users.l2_propagated_at
  IS 'L2→L3 배치 동기화 완료 시각 (10분 주기).';
COMMENT ON COLUMN users.l3_propagated_at
  IS 'L3→L4 배치 동기화 완료 시각 (1시간 주기).';


-- ================================================================
-- SECTION 2: 신규 테이블 4개
-- ================================================================

-- ── 2-A. gduda_nodes — GDUDA 노드 레지스트리 ────────────────────
-- Phase 1: 한림읍 L1 노드 1개를 Supabase로 구현한 레지스트리
-- Phase 2: 제주도 전체 L1·L2 노드 목록
-- Phase 3: 전국 노드 목록 (L3·L4는 외부 DHT로 이관)

CREATE TABLE IF NOT EXISTS gduda_nodes (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  node_id       text        NOT NULL UNIQUE,
    -- 예) KR-JEJU-JEJU-HANLIM
  node_level    smallint    NOT NULL,
    -- 1=읍면동, 2=시군구, 3=광역, 4=국가, 5=글로벌
  node_name     text        NOT NULL,
    -- 예) 제주시 한림읍
  parent_node   text,
    -- 상위 노드 ID. L5는 NULL
  endpoint_url  text,
    -- Phase 2+: 원격 노드 API 엔드포인트
  user_count    integer     NOT NULL DEFAULT 0,
  is_local      boolean     NOT NULL DEFAULT true,
    -- true = 이 Supabase가 직접 관리하는 노드
  is_active     boolean     NOT NULL DEFAULT true,
  lat           float8,
    -- 노드 중심 위도 (근접 노드 탐색용)
  lng           float8,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE gduda_nodes
  IS 'GDUDA OpenHash 5계층 노드 레지스트리. Phase 1: Supabase 로컬 노드만. Phase 2+: 원격 노드 추가.';
COMMENT ON COLUMN gduda_nodes.node_id
  IS '계층 식별자. 형식: {L4코드}-{L3코드}-{L2코드}-{L1코드}. 예) KR-JEJU-JEJU-HANLIM';
COMMENT ON COLUMN gduda_nodes.is_local
  IS 'true = 이 Supabase 인스턴스가 직접 서비스하는 노드';


-- ── 2-B. gduda_routing_table — 계층 라우팅 테이블 ───────────────
-- GDUDA_SEARCH() 알고리즘의 라우팅 테이블을 SQL로 구현
-- Phase 1: L1(한림읍) 내 사용자 → user_profiles로 직접 조회
-- Phase 2: 타 L1 노드 → endpoint_url로 원격 질의

CREATE TABLE IF NOT EXISTS gduda_routing_table (
  id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  from_node       text        NOT NULL,
    -- 질의 출발 노드 ID
  to_node         text        NOT NULL,
    -- 목적지 노드 ID
  primary_guid    text,
    -- 특정 사용자 직접 라우팅 (NULL이면 노드 전체 라우팅)
  nickname_hash   text,
    -- 닉네임 기반 라우팅 캐시 (§9.3)
  hop_count       smallint    NOT NULL DEFAULT 1,
  latency_ms      integer,
    -- 마지막 측정 지연 시간
  last_verified   timestamptz,
  ttl_seconds     integer     NOT NULL DEFAULT 86400,
    -- 캐시 유효 시간 (초). 닉네임은 86400(24시간)
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_routing UNIQUE (from_node, to_node, COALESCE(primary_guid,''), COALESCE(nickname_hash,''))
);

COMMENT ON TABLE gduda_routing_table
  IS 'GDUDA 계층 라우팅 테이블. GDUDA_SEARCH() §4.2 구현체.';
COMMENT ON COLUMN gduda_routing_table.nickname_hash
  IS 'SHA-256(nickname). 닉네임→GUID 역방향 조회 캐시 (§9.3).';
COMMENT ON COLUMN gduda_routing_table.ttl_seconds
  IS '캐시 만료 초. 닉네임: 86400(24h), 사용자 위치: 3600(1h).';


-- ── 2-C. gduda_propagation_log — 등록 전파 이력 ────────────────
-- §9.1 지연 전파(Lazy Propagation) 배치 작업 추적
-- L1→L2 즉시 / L2→L3 10분 / L3→L4 1시간 배치

CREATE TABLE IF NOT EXISTS gduda_propagation_log (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  primary_guid  text        NOT NULL,
  event_type    text        NOT NULL,
    -- 'REGISTER' | 'UPDATE' | 'DEACTIVATE' | 'NICKNAME_CHANGE'
  from_level    smallint    NOT NULL,
  to_level      smallint    NOT NULL,
  status        text        NOT NULL DEFAULT 'pending',
    -- 'pending' | 'propagated' | 'failed'
  payload       jsonb,
    -- 전파할 데이터 스냅샷
  scheduled_at  timestamptz NOT NULL DEFAULT now(),
  propagated_at timestamptz,
  error_msg     text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE gduda_propagation_log
  IS 'GDUDA 등록 전파 이력. §9.1 지연 전파 배치 스케줄러가 이 테이블을 읽어 처리.';
COMMENT ON COLUMN gduda_propagation_log.event_type
  IS 'REGISTER=신규등록, UPDATE=정보변경, DEACTIVATE=탈퇴, NICKNAME_CHANGE=닉네임변경';
COMMENT ON COLUMN gduda_propagation_log.status
  IS 'pending=대기, propagated=완료, failed=실패(재시도 대상)';


-- ── 2-D. gduda_openid_blocks — OpenHash 블록 로컬 캐시 ──────────
-- Phase 1: OpenHash 미구현 → 로컬 Supabase에 블록 기록
-- Phase 3: 실제 OpenHash 네트워크로 이관 후 이 테이블은 캐시만 유지

CREATE TABLE IF NOT EXISTS gduda_openid_blocks (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  block_hash    text        NOT NULL UNIQUE,
    -- SHA-256(prev_hash + payload + timestamp)
  prev_hash     text,
    -- 이전 블록 해시 (genesis는 NULL)
  block_type    text        NOT NULL,
    -- 'USER_REGISTER' | 'USER_UPDATE' | 'USER_DEACTIVATE'
    -- | 'NICKNAME_REGISTER' | 'NICKNAME_RELEASE'
    -- | 'REGIONAL_DB_ELECT' | 'MSG_DELIVERED'
  primary_guid  text        NOT NULL,
  payload       jsonb       NOT NULL,
    -- { primary_guid, current_ipv6, public_key_hash,
    --   l1_node, event_data, ... }
  signature     text        NOT NULL,
    -- ECDSA(block_hash, private_key) — 사용자 자기 서명
  is_verified   boolean     NOT NULL DEFAULT false,
    -- Phase 2+: 타 노드 검증 완료 여부
  created_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE gduda_openid_blocks
  IS 'OpenHash 블록 로컬 구현. Phase 1: 전체 원본. Phase 3: 캐시만 유지.';
COMMENT ON COLUMN gduda_openid_blocks.block_type
  IS 'OpenHash §10 이벤트 유형 전체 목록';
COMMENT ON COLUMN gduda_openid_blocks.is_verified
  IS 'Phase 2+에서 타 노드 2/3 이상 서명 검증 완료 여부';


-- ================================================================
-- SECTION 3: 인덱스
-- ================================================================

-- user_profiles GDUDA 컬럼 인덱스
CREATE INDEX IF NOT EXISTS idx_up_primary_guid
  ON user_profiles(primary_guid) WHERE primary_guid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_up_current_ipv6
  ON user_profiles(current_ipv6) WHERE current_ipv6 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_up_l1_node
  ON user_profiles(l1_node) WHERE l1_node IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_up_l2_node
  ON user_profiles(l2_node) WHERE l2_node IS NOT NULL;

-- 복합 인덱스: L1 노드 + entity_type + is_public
-- search_entities() p_l1_node 파라미터 사용 시 핵심
CREATE INDEX IF NOT EXISTS idx_up_l1_entity_public
  ON user_profiles(l1_node, entity_type, is_public)
  WHERE is_public = TRUE;

-- gduda_nodes
CREATE INDEX IF NOT EXISTS idx_gduda_nodes_level
  ON gduda_nodes(node_level, is_active);

CREATE INDEX IF NOT EXISTS idx_gduda_nodes_parent
  ON gduda_nodes(parent_node) WHERE parent_node IS NOT NULL;

-- gduda_routing_table
CREATE INDEX IF NOT EXISTS idx_routing_from_node
  ON gduda_routing_table(from_node);

CREATE INDEX IF NOT EXISTS idx_routing_nickname
  ON gduda_routing_table(nickname_hash) WHERE nickname_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_routing_guid
  ON gduda_routing_table(primary_guid) WHERE primary_guid IS NOT NULL;

-- gduda_propagation_log
CREATE INDEX IF NOT EXISTS idx_prop_status_scheduled
  ON gduda_propagation_log(status, scheduled_at)
  WHERE status = 'pending';

-- gduda_openid_blocks
CREATE INDEX IF NOT EXISTS idx_blocks_primary_guid
  ON gduda_openid_blocks(primary_guid);

CREATE INDEX IF NOT EXISTS idx_blocks_type
  ON gduda_openid_blocks(block_type, created_at DESC);


-- ================================================================
-- SECTION 4: search_entities() RPC 갱신 (하위 호환)
-- 기존 파라미터 전부 유지 + p_l1_node, p_l2_node, p_primary_guid 추가
-- 기존 호출 코드는 수정 없이 그대로 동작
-- ================================================================

CREATE OR REPLACE FUNCTION search_entities(
  p_entity_type  text    DEFAULT NULL,
  p_keyword      text    DEFAULT NULL,
  p_occupation   text    DEFAULT NULL,
  p_address      text    DEFAULT NULL,
  p_gdc_only     boolean DEFAULT false,
  p_trust_min    text    DEFAULT NULL,
  p_lat          float8  DEFAULT NULL,
  p_lng          float8  DEFAULT NULL,
  p_sort         text    DEFAULT 'rating',
  p_limit        int     DEFAULT 10,
  p_offset       int     DEFAULT 0,
  p_exclude_guid text    DEFAULT NULL,
  -- ★ GDUDA 추가 파라미터 (기존 호출 시 NULL → 동작 동일)
  p_l1_node      text    DEFAULT NULL,  -- GDUDA L1 계층 필터
  p_l2_node      text    DEFAULT NULL,  -- GDUDA L2 계층 필터
  p_primary_guid text    DEFAULT NULL   -- Primary GUID 직접 조회
)
RETURNS TABLE (
  guid          text,
  primary_guid  text,   -- ★ GDUDA Primary GUID 추가 반환
  current_ipv6  text,   -- ★ GDUDA Current IPv6 추가 반환
  l1_node       text,   -- ★ GDUDA L1 노드 추가 반환
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
  WITH trust_order AS (
    SELECT 'L0'::text AS lvl, 0 AS ord UNION ALL
    SELECT 'L1',              1        UNION ALL
    SELECT 'L2',              2        UNION ALL
    SELECT 'L3',              3
  ),
  base AS (
    SELECT
      up.guid,
      up.primary_guid,
      up.current_ipv6,
      up.l1_node,
      up.entity_type,
      up.name,
      up.occupation,
      up.services,
      up.address,
      up.website,
      up.is_public,
      up.extra,
      COALESCE(utl.trust_level, 'L0')   AS trust_level,
      COALESCE(ugs.gdc_accepted, false)  AS gdc_accepted,
      COALESCE(sr.weighted_avg,  0)      AS rating_avg,
      COALESCE(sr.review_count,  0)      AS review_count,
      ll.lat,
      ll.lng,
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
      -- 기존 필터 (하위 호환)
      AND (p_exclude_guid IS NULL OR up.guid        <> p_exclude_guid)
      AND (p_entity_type  IS NULL OR up.entity_type  = p_entity_type)
      AND (p_occupation   IS NULL
           OR up.occupation ILIKE '%' || p_occupation || '%')
      AND (p_keyword IS NULL
           OR up.name        ILIKE '%' || p_keyword || '%'
           OR up.occupation  ILIKE '%' || p_keyword || '%'
           OR EXISTS (
               SELECT 1 FROM unnest(up.services) svc
               WHERE svc ILIKE '%' || p_keyword || '%'
             ))
      AND (p_address IS NULL
           OR up.address ILIKE '%' || p_address || '%'
           OR ll.address ILIKE '%' || p_address || '%')
      AND (p_gdc_only = FALSE OR ugs.gdc_accepted = TRUE)
      AND (p_trust_min IS NULL
           OR COALESCE(to_.ord, 0) >= (
               SELECT ord FROM trust_order WHERE lvl = p_trust_min
             ))
      -- ★ GDUDA 계층 필터 (신규, NULL이면 무시 → 하위 호환)
      AND (p_l1_node      IS NULL OR up.l1_node      = p_l1_node)
      AND (p_l2_node      IS NULL OR up.l2_node      = p_l2_node)
      AND (p_primary_guid IS NULL OR up.primary_guid = p_primary_guid)
  )
  SELECT
    guid, primary_guid, current_ipv6, l1_node,
    entity_type, name, occupation, services,
    address, website, is_public, extra,
    trust_level, gdc_accepted,
    rating_avg::numeric, review_count::integer,
    lat, lng, distance_km
  FROM base
  ORDER BY
    CASE WHEN p_sort = 'distance' AND distance_km IS NOT NULL
         THEN distance_km END ASC NULLS LAST,
    CASE WHEN p_sort = 'rating'
         THEN rating_avg END DESC NULLS LAST,
    CASE WHEN p_sort = 'review_count'
         THEN review_count END DESC NULLS LAST,
    trust_ord DESC
  LIMIT  p_limit
  OFFSET p_offset;
$$;

COMMENT ON FUNCTION search_entities IS
  'users.hondi.net 엔티티 통합 검색 RPC v2.1.
   기존 파라미터 완전 하위 호환.
   GDUDA 추가: p_l1_node, p_l2_node, p_primary_guid.
   반환: primary_guid, current_ipv6, l1_node 추가.
   SP-USERS-v2_0 STEP 05 참조.';

GRANT EXECUTE ON FUNCTION search_entities TO anon, authenticated;


-- ================================================================
-- SECTION 5: 초기 데이터
-- ================================================================

-- ── 5-A. 한림읍 L1 노드 등록 (Phase 1 파일럿) ──────────────────
INSERT INTO gduda_nodes
  (node_id, node_level, node_name, parent_node,
   is_local, is_active, lat, lng)
VALUES
  -- L1: 한림읍 (파일럿 로컬 노드)
  ('KR-JEJU-JEJU-HANLIM', 1, '제주시 한림읍',
   'KR-JEJU-JEJU', true, true, 33.4135, 126.2680),
  -- L2: 제주시 (상위 노드, 원격 — Phase 2에서 활성화)
  ('KR-JEJU-JEJU', 2, '제주특별자치도 제주시',
   'KR-JEJU', false, false, 33.4996, 126.5312),
  -- L3: 제주도 (광역, 원격 — Phase 2에서 활성화)
  ('KR-JEJU', 3, '제주특별자치도',
   'KR', false, false, 33.3617, 126.5292),
  -- L4: 대한민국 (국가, 원격 — Phase 3에서 활성화)
  ('KR', 4, '대한민국',
   NULL, false, false, 36.0000, 127.5000)
ON CONFLICT (node_id) DO UPDATE SET
  node_name  = EXCLUDED.node_name,
  updated_at = now();


-- ── 5-B. 한림읍 기존 사용자 l1_node 일괄 설정 ──────────────────
UPDATE user_profiles
SET
  l1_node      = 'KR-JEJU-JEJU-HANLIM',
  l2_node      = 'KR-JEJU-JEJU',
  l3_node      = 'KR-JEJU',
  registered_l1 = 'KR-JEJU-JEJU-HANLIM'
WHERE
  (address ILIKE '%한림읍%' OR address ILIKE '%한림%')
  AND l1_node IS NULL;

-- ── 5-C. gduda_nodes user_count 갱신 ────────────────────────────
UPDATE gduda_nodes
SET user_count = (
  SELECT COUNT(*) FROM user_profiles
  WHERE l1_node = gduda_nodes.node_id
    AND is_public = TRUE
)
WHERE node_id = 'KR-JEJU-JEJU-HANLIM';

-- ── 5-D. Genesis 블록 (OpenHash 체인 시작점) ────────────────────
INSERT INTO gduda_openid_blocks
  (block_hash, prev_hash, block_type, primary_guid, payload, signature, is_verified)
VALUES (
  'GENESIS-' || encode(sha256('gopang-hanlim-pilot-2026'::bytea), 'hex'),
  NULL,
  'USER_REGISTER',
  'SYSTEM',
  '{"type":"GENESIS","node":"KR-JEJU-JEJU-HANLIM","pilot":"제주시 한림읍","started_at":"2026-06-08"}'::jsonb,
  'SYSTEM_GENESIS',
  true
)
ON CONFLICT (block_hash) DO NOTHING;


-- ================================================================
-- SECTION 6: RLS 정책
-- ================================================================

ALTER TABLE gduda_nodes            ENABLE ROW LEVEL SECURITY;
ALTER TABLE gduda_routing_table    ENABLE ROW LEVEL SECURITY;
ALTER TABLE gduda_propagation_log  ENABLE ROW LEVEL SECURITY;
ALTER TABLE gduda_openid_blocks    ENABLE ROW LEVEL SECURITY;

-- gduda_nodes: 누구나 읽기, 서비스 롤만 쓰기
DROP POLICY IF EXISTS nodes_select_public ON gduda_nodes;
CREATE POLICY nodes_select_public
  ON gduda_nodes FOR SELECT USING (true);

DROP POLICY IF EXISTS nodes_write_service ON gduda_nodes;
CREATE POLICY nodes_write_service
  ON gduda_nodes FOR ALL USING (auth.role() = 'service_role');

-- gduda_routing_table: 누구나 읽기, 서비스 롤만 쓰기
DROP POLICY IF EXISTS routing_select_public ON gduda_routing_table;
CREATE POLICY routing_select_public
  ON gduda_routing_table FOR SELECT USING (true);

DROP POLICY IF EXISTS routing_write_service ON gduda_routing_table;
CREATE POLICY routing_write_service
  ON gduda_routing_table FOR ALL USING (auth.role() = 'service_role');

-- gduda_propagation_log: 서비스 롤만 읽기/쓰기
DROP POLICY IF EXISTS prop_service_only ON gduda_propagation_log;
CREATE POLICY prop_service_only
  ON gduda_propagation_log FOR ALL USING (auth.role() = 'service_role');

-- gduda_openid_blocks: 누구나 읽기 (공개 원장), 서비스 롤만 쓰기
DROP POLICY IF EXISTS blocks_select_public ON gduda_openid_blocks;
CREATE POLICY blocks_select_public
  ON gduda_openid_blocks FOR SELECT USING (true);

DROP POLICY IF EXISTS blocks_write_service ON gduda_openid_blocks;
CREATE POLICY blocks_write_service
  ON gduda_openid_blocks FOR ALL USING (auth.role() = 'service_role');


-- ================================================================
-- 실행 후 확인 쿼리
-- ================================================================

/*
-- 1. 추가된 컬럼 확인
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'user_profiles'
  AND column_name IN (
    'primary_guid','current_ipv6','l1_node','l2_node','l3_node',
    'public_key','registered_l1'
  )
ORDER BY column_name;

-- 2. 신규 테이블 확인
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name LIKE 'gduda_%'
ORDER BY table_name;

-- 3. 한림읍 노드 확인
SELECT node_id, node_name, node_level, is_local, is_active, user_count
FROM gduda_nodes ORDER BY node_level;

-- 4. search_entities() GDUDA 파라미터 테스트
SELECT name, l1_node, primary_guid, distance_km
FROM search_entities(
  p_l1_node => 'KR-JEJU-JEJU-HANLIM',
  p_entity_type => 'org',
  p_lat => 33.4135,
  p_lng => 126.2680,
  p_sort => 'distance',
  p_limit => 5
);

-- 5. Genesis 블록 확인
SELECT block_hash, block_type, created_at
FROM gduda_openid_blocks
WHERE primary_guid = 'SYSTEM';
*/
