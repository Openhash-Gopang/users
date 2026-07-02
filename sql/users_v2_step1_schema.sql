-- =============================================================
-- users.hondi.net  Schema Migration  v2.0 → v2.2
-- Step 1: 테이블 구조 변경 및 신규 테이블 생성
-- 참조: Gopang Auth & Discovery v2.2 §16, §17, §13.6, §14.4, §15
-- 실행 순서: 이 파일 전체를 Supabase SQL Editor에서 한 번에 실행
-- =============================================================

-- ─────────────────────────────────────────────────────────────
-- §1. user_nicknames 개정
--     현재: nickname_hash UNIQUE (1 hash : 1 GUID) — 폐기
--     변경: 중복 닉네임 허용 (§17), v2 해시 추가, handle 추가
-- ─────────────────────────────────────────────────────────────

-- 1-1. 기존 UNIQUE 제약 제거 (중복 닉네임 허용을 위해)
ALTER TABLE user_nicknames
  DROP CONSTRAINT IF EXISTS uq_nickname_hash;

DROP INDEX IF EXISTS uq_nickname_hash;

-- 1-2. 신규 컬럼 추가
ALTER TABLE user_nicknames
  ADD COLUMN IF NOT EXISTS nickname_hash_v2 text,         -- SHA-256("lang_code:닉네임")
  ADD COLUMN IF NOT EXISTS lang_code        text DEFAULT 'ko',  -- BCP 47
  ADD COLUMN IF NOT EXISTS script           text,          -- ISO 15924 (Hang, Latn 등)
  ADD COLUMN IF NOT EXISTS handle           text,          -- @닉네임#GUID[:4]
  ADD COLUMN IF NOT EXISTS verified         boolean DEFAULT false,
  ADD COLUMN IF NOT EXISTS issuer_guid      text;          -- 검증 기관 GUID (nullable)

-- 1-3. handle 유니크 인덱스 (§17.3 — handle은 전역 유일)
CREATE UNIQUE INDEX IF NOT EXISTS idx_nicknames_handle
  ON user_nicknames (handle)
  WHERE handle IS NOT NULL;

-- 1-4. v2 해시 + lang_code 복합 인덱스 (§16.5)
CREATE INDEX IF NOT EXISTS idx_nicknames_hash_v2_lang
  ON user_nicknames (nickname_hash_v2, lang_code)
  WHERE nickname_hash_v2 IS NOT NULL;

-- 1-5. v1 해시 인덱스 유지 (§16.8 하위 호환 — 폴백용)
--      기존 idx_user_nicknames_hash 는 DROP 하지 않고 그대로 둠

-- 1-6. guid + status 복합 인덱스 (active 닉네임 조회 최적화)
CREATE INDEX IF NOT EXISTS idx_nicknames_guid_status
  ON user_nicknames (guid, status)
  WHERE status = 'active';


-- ─────────────────────────────────────────────────────────────
-- §2. nickname_cache 테이블 신규 생성
--     Phase 1: Supabase 단일 DB가 L1~L3 캐시 역할을 겸함
--     §9.3, §13.5, §16.5, §17.3
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS nickname_cache (
  -- 복합 기본키: 1 hash : N GUID 허용 (§17.3)
  nickname_hash    text        NOT NULL,  -- SHA-256("ko:닉네임") v2
  primary_guid     text        NOT NULL,  -- user_profiles.primary_guid 참조

  -- handle: @닉네임#GUID[:4] — 전역 유일 (§17.2)
  handle           text        NOT NULL,

  -- 다국어 지원 (§16.2, §16.5)
  lang_code        text        NOT NULL DEFAULT 'ko',  -- BCP 47
  script           text,                               -- ISO 15924

  -- 검증 배지 (§17.2 ③)
  verified         boolean     NOT NULL DEFAULT false,
  issuer_guid      text,                               -- nullable

  -- GDUDA 계층 노드 (§13.5)
  l1_node          text,
  l2_node          text,
  l3_node          text,

  -- TTL 관리 (§9.3)
  ttl              integer     NOT NULL DEFAULT 86400, -- 초 단위 (24시간)
  updated_at       timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (nickname_hash, primary_guid)
);

-- handle 직접 검색 인덱스 (§17.4 — ~2ms 조회 목표)
CREATE UNIQUE INDEX IF NOT EXISTS idx_nickname_cache_handle
  ON nickname_cache (handle);

-- 언어 + 해시 복합 인덱스 (§16.4 ④ KR L4 조회)
CREATE INDEX IF NOT EXISTS idx_nickname_cache_lang_hash
  ON nickname_cache (lang_code, nickname_hash);

-- l3_node 필터 인덱스 (§13.5 경로 A — 지역 먼저)
CREATE INDEX IF NOT EXISTS idx_nickname_cache_l3
  ON nickname_cache (l3_node, nickname_hash)
  WHERE l3_node IS NOT NULL;

-- l1_node 필터 인덱스 (§13.3 읍면동 수준 조회)
CREATE INDEX IF NOT EXISTS idx_nickname_cache_l1
  ON nickname_cache (l1_node, nickname_hash)
  WHERE l1_node IS NOT NULL;

-- verified 우선 정렬 지원 (§17.3 ORDER BY verified DESC)
CREATE INDEX IF NOT EXISTS idx_nickname_cache_verified
  ON nickname_cache (nickname_hash, verified DESC, updated_at DESC);


-- ─────────────────────────────────────────────────────────────
-- §3. user_attributes 테이블 신규 생성
--     Phase 1 AIS (Attribute Index Service) — Supabase 구현
--     §14.4, §15.7
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_attributes (
  id               bigserial   PRIMARY KEY,

  -- 소유자 식별 (§15.3)
  primary_guid     text        NOT NULL,
  current_ipv6     text,                    -- IPv6 = 분산 PAR 키 (§15.2)

  -- 속성 내용 (§14.4)
  attr_type        text        NOT NULL,    -- 'education' | 'occupation' | 'location' | 'verification'
  attr_value_hash  text,                    -- SHA-256(원본) — 원본 비보관 원칙 (§14.4)

  -- 교육 속성 (attr_type = 'education')
  school_guid      text,                    -- 기관 GUID
  enroll_year      integer,                 -- 입학연도
  graduate_year    integer,                 -- 졸업연도 (nullable)
  role             text,                    -- 'student' | 'professor' | 'staff'

  -- 직업 속성 (attr_type = 'occupation')
  field            text,                    -- 직업 분야 코드

  -- 위치 속성 (attr_type = 'location')
  attr_l3_node     text,
  attr_l2_node     text,

  -- 공개 범위 (§14.4, §15.3)
  is_public        boolean     NOT NULL DEFAULT true,

  -- 자발적 제출 증명 (§14.4)
  owner_signature  text,                    -- ECDSA(attrs, 소유자 개인키)
  submitted_at     timestamptz NOT NULL DEFAULT now(),

  -- 철회 지원 (§14.4)
  is_active        boolean     NOT NULL DEFAULT true,
  revoked_at       timestamptz
);

-- primary_guid + attr_type 복합 조회 인덱스
CREATE INDEX IF NOT EXISTS idx_user_attr_guid_type
  ON user_attributes (primary_guid, attr_type)
  WHERE is_active = true;

-- 교육 속성 검색 인덱스 (§14.3 ③ AIS 필터)
CREATE INDEX IF NOT EXISTS idx_user_attr_education
  ON user_attributes (school_guid, enroll_year, is_public)
  WHERE attr_type = 'education' AND is_active = true;

-- IPv6 기반 PAR 조회 인덱스 (§15.5 ④)
CREATE INDEX IF NOT EXISTS idx_user_attr_ipv6
  ON user_attributes (current_ipv6)
  WHERE current_ipv6 IS NOT NULL AND is_active = true;


-- ─────────────────────────────────────────────────────────────
-- §4. lang_node_map 테이블 신규 생성
--     언어 코드 → GDUDA 우선 조회 노드 매핑 (§16.3)
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS lang_node_map (
  lang_code        text        NOT NULL,    -- BCP 47 언어 코드
  priority_nodes   text[]      NOT NULL,    -- 우선 조회 L4 노드 목록
  fallback_global  boolean     NOT NULL DEFAULT false,  -- true면 L5 글로벌 조회
  note             text,
  updated_at       timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (lang_code)
);

-- 기본 데이터 삽입 (§16.3 표)
INSERT INTO lang_node_map (lang_code, priority_nodes, fallback_global, note)
VALUES
  ('ko', ARRAY['KR'],          false, '한국어: 99%+ 사용자가 KR 노드'),
  ('ja', ARRAY['JP'],          false, '일본어: 일본 집중'),
  ('zh', ARRAY['CN','TW','HK'],false, '중국어: 3개 주요 노드'),
  ('ar', ARRAY['SA','EG','AE'],true,  '아랍어: 다수 분산, 글로벌 보완'),
  ('en', ARRAY[]::text[],      true,  '영어: 영어권 분산 → L5 글로벌')
ON CONFLICT (lang_code) DO UPDATE SET
  priority_nodes  = EXCLUDED.priority_nodes,
  fallback_global = EXCLUDED.fallback_global,
  note            = EXCLUDED.note,
  updated_at      = now();


-- ─────────────────────────────────────────────────────────────
-- §5. region_node_map 테이블 신규 생성
--     자연어 지역 표현 → GDUDA 노드 식별자 매핑 (§13.6)
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS region_node_map (
  id               bigserial   PRIMARY KEY,
  region_text      text        NOT NULL UNIQUE,  -- 자연어 입력 (예: "한림읍")
  node_id          text        NOT NULL,          -- GDUDA 노드 식별자
  node_level       smallint    NOT NULL,          -- 1=읍면동, 2=시군구, 3=광역, 4=국가
  country_code     text        NOT NULL DEFAULT 'KR',
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_region_node_text
  ON region_node_map (region_text);

CREATE INDEX IF NOT EXISTS idx_region_node_level
  ON region_node_map (node_level, country_code);

-- 제주도 파일럿 기본 매핑 데이터 (§13.6)
INSERT INTO region_node_map (region_text, node_id, node_level, country_code)
VALUES
  -- L1 (읍면동)
  ('한림읍',       'KR-JEJU-JEJU-HANLIM',  1, 'KR'),
  ('이도1동',      'KR-JEJU-JEJU-IDO1',    1, 'KR'),
  ('이도2동',      'KR-JEJU-JEJU-IDO2',    1, 'KR'),
  ('연동',         'KR-JEJU-JEJU-YEON',    1, 'KR'),
  ('노형동',       'KR-JEJU-JEJU-NOHYUNG', 1, 'KR'),
  ('애월읍',       'KR-JEJU-JEJU-AEWOL',   1, 'KR'),
  ('조천읍',       'KR-JEJU-JEJU-JOCHEON', 1, 'KR'),
  ('구좌읍',       'KR-JEJU-JEJU-GUJWA',   1, 'KR'),
  ('성산읍',       'KR-JEJU-SEOGWIPO-SEONGSAN', 1, 'KR'),
  ('서귀포시',     'KR-JEJU-SEOGWIPO',     2, 'KR'),
  -- L2 (시군구)
  ('제주시',       'KR-JEJU-JEJU',         2, 'KR'),
  -- L3 (광역)
  ('제주도',       'KR-JEJU',              3, 'KR'),
  ('제주특별자치도','KR-JEJU',             3, 'KR'),
  -- 서울 샘플 (확장용)
  ('서울',         'KR-SEOUL',             3, 'KR'),
  ('강남구',       'KR-SEOUL-GN',          2, 'KR'),
  ('역삼동',       'KR-SEOUL-GN-YS',       1, 'KR')
ON CONFLICT (region_text) DO UPDATE SET
  node_id      = EXCLUDED.node_id,
  node_level   = EXCLUDED.node_level,
  updated_at   = now();


-- ─────────────────────────────────────────────────────────────
-- §6. user_profiles — l3_node 인덱스 추가 (이미 컬럼은 존재)
-- ─────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_up_l3_node
  ON user_profiles (l3_node)
  WHERE l3_node IS NOT NULL;

-- primary_guid + l1_node 복합 인덱스 (§13.3 경로 A 최적화)
CREATE INDEX IF NOT EXISTS idx_up_primary_guid_l1
  ON user_profiles (primary_guid, l1_node)
  WHERE primary_guid IS NOT NULL;


-- ─────────────────────────────────────────────────────────────
-- 완료 확인
-- ─────────────────────────────────────────────────────────────
DO $$
BEGIN
  RAISE NOTICE '=== Step 1 완료 ===';
  RAISE NOTICE 'user_nicknames: handle, nickname_hash_v2, lang_code, verified 컬럼 추가';
  RAISE NOTICE 'nickname_cache: 신규 생성 (복합 PK: nickname_hash + primary_guid)';
  RAISE NOTICE 'user_attributes: 신규 생성 (Phase 1 AIS)';
  RAISE NOTICE 'lang_node_map: 신규 생성 + 기본 5개 언어 데이터';
  RAISE NOTICE 'region_node_map: 신규 생성 + 제주도 16개 지역 매핑';
  RAISE NOTICE 'user_profiles: l3_node 인덱스 추가';
  RAISE NOTICE '다음 단계: users_v2_step2_rpc.sql 실행';
END $$;
