-- =============================================================
-- users.hondi.net  Data Migration  v2.0 → v2.2
-- Step 3: 기존 더미 데이터에 v2 식별자 반영
-- 실행 순서: Step 1, 2 완료 후 실행
-- =============================================================

-- ─────────────────────────────────────────────────────────────
-- §1. user_nicknames — 기존 레코드에 v2 컬럼 값 설정
--     보영반점, 한림중화반점, 금능반점
--     handle = @닉네임#primary_guid[:4]
-- ─────────────────────────────────────────────────────────────

-- 보영반점
UPDATE user_nicknames un
SET
  lang_code        = 'ko',
  script           = 'Hang',
  -- nickname_hash_v2: 클라이언트에서 SHA-256("ko:보영반점") 계산 예정
  -- Phase 1에서는 placeholder로 nickname_hash_v1 기반 임시값 사용
  nickname_hash_v2 = 'v2_placeholder_' || un.nickname_hash,
  handle           = '@' || un.nickname || '#' || LEFT(
                       COALESCE(
                         (SELECT primary_guid FROM user_profiles WHERE guid = un.guid LIMIT 1),
                         un.guid
                       ), 4
                     ),
  verified         = false
WHERE un.guid IN (
  SELECT guid FROM user_profiles WHERE name = '보영반점'
);

-- 한림중화반점
UPDATE user_nicknames un
SET
  lang_code        = 'ko',
  script           = 'Hang',
  nickname_hash_v2 = 'v2_placeholder_' || un.nickname_hash,
  handle           = '@' || un.nickname || '#' || LEFT(
                       COALESCE(
                         (SELECT primary_guid FROM user_profiles WHERE guid = un.guid LIMIT 1),
                         un.guid
                       ), 4
                     ),
  verified         = false
WHERE un.guid IN (
  SELECT guid FROM user_profiles WHERE name = '한림중화반점'
);

-- 금능반점
UPDATE user_nicknames un
SET
  lang_code        = 'ko',
  script           = 'Hang',
  nickname_hash_v2 = 'v2_placeholder_' || un.nickname_hash,
  handle           = '@' || un.nickname || '#' || LEFT(
                       COALESCE(
                         (SELECT primary_guid FROM user_profiles WHERE guid = un.guid LIMIT 1),
                         un.guid
                       ), 4
                     ),
  verified         = false
WHERE un.guid IN (
  SELECT guid FROM user_profiles WHERE name = '금능반점'
);


-- ─────────────────────────────────────────────────────────────
-- §2. nickname_cache — 3개 업체 캐시 레코드 삽입
--     Phase 1: Supabase DB가 L1(한림읍) 캐시 역할 겸임
-- ─────────────────────────────────────────────────────────────

INSERT INTO nickname_cache (
  nickname_hash, primary_guid, handle,
  lang_code, script, verified, issuer_guid,
  l1_node, l2_node, l3_node, ttl, updated_at
)
SELECT
  un.nickname_hash                           AS nickname_hash,
  COALESCE(up.primary_guid, up.guid)         AS primary_guid,
  COALESCE(un.handle, '@' || un.nickname || '#' || LEFT(COALESCE(up.primary_guid, up.guid), 4)) AS handle,
  COALESCE(un.lang_code, 'ko')               AS lang_code,
  COALESCE(un.script, 'Hang')                AS script,
  COALESCE(un.verified, false)               AS verified,
  un.issuer_guid,
  up.l1_node,
  up.l2_node,
  up.l3_node,
  86400,
  now()
FROM user_nicknames un
JOIN user_profiles up ON up.guid = un.guid
WHERE up.name IN ('보영반점', '한림중화반점', '금능반점')
  AND un.status = 'active'
ON CONFLICT (nickname_hash, primary_guid) DO UPDATE SET
  handle     = EXCLUDED.handle,
  lang_code  = EXCLUDED.lang_code,
  script     = EXCLUDED.script,
  verified   = EXCLUDED.verified,
  l1_node    = EXCLUDED.l1_node,
  l2_node    = EXCLUDED.l2_node,
  l3_node    = EXCLUDED.l3_node,
  updated_at = now();


-- ─────────────────────────────────────────────────────────────
-- §3. user_profiles — l3_node 값 설정 (한림읍 = 제주도 L3)
-- ─────────────────────────────────────────────────────────────

UPDATE user_profiles
SET l3_node = 'KR-JEJU'
WHERE address ILIKE '%한림읍%'
  AND l3_node IS NULL;


-- ─────────────────────────────────────────────────────────────
-- §4. 검증 쿼리 — 마이그레이션 결과 확인
-- ─────────────────────────────────────────────────────────────

-- 4-1. user_nicknames v2 컬럼 확인
SELECT
  un.nickname,
  un.handle,
  un.lang_code,
  un.verified,
  up.primary_guid,
  up.l1_node,
  up.l3_node
FROM user_nicknames un
JOIN user_profiles up ON up.guid = un.guid
WHERE up.name IN ('보영반점', '한림중화반점', '금능반점')
ORDER BY up.name;

-- 4-2. nickname_cache 확인
SELECT
  nickname_hash,
  primary_guid,
  handle,
  lang_code,
  l1_node,
  l3_node,
  verified,
  updated_at
FROM nickname_cache
ORDER BY updated_at DESC;

-- 4-3. search_entities() 신규 반환 컬럼 확인
SELECT
  name,
  handle,
  verified,
  lang_code,
  distance_km,
  rating_avg,
  trust_level
FROM search_entities(
  p_keyword  => '짜장면',
  p_address  => '한림읍',
  p_lat      => 33.4135,
  p_lng      => 126.2680,
  p_sort     => 'distance'
);

-- 4-4. region_node_map 확인
SELECT region_text, node_id, node_level
FROM region_node_map
ORDER BY node_level, region_text;

-- 4-5. lang_node_map 확인
SELECT lang_code, priority_nodes, fallback_global
FROM lang_node_map
ORDER BY lang_code;


-- ─────────────────────────────────────────────────────────────
-- 완료 확인
-- ─────────────────────────────────────────────────────────────
DO $$
BEGIN
  RAISE NOTICE '=== Step 3 완료 ===';
  RAISE NOTICE 'user_nicknames: 3개 업체 handle/lang_code/verified 설정';
  RAISE NOTICE 'nickname_cache: 3개 업체 캐시 레코드 삽입';
  RAISE NOTICE 'user_profiles: l3_node = KR-JEJU 설정 (한림읍 주소 기준)';
  RAISE NOTICE '검증 쿼리 4개 결과를 확인하세요';
  RAISE NOTICE '=== SQL Migration v2.2 전체 완료 ===';
END $$;
