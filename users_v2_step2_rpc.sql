-- =============================================================
-- users.gopang.net  RPC Migration  v2.0 → v2.2
-- Step 2: search_entities 개정 + search_by_attributes 신규 생성
-- 참조: Gopang Auth & Discovery v2.2 §13, §14, §16, §17
-- 최종 수정: nickname_cache LATERAL JOIN 방식 (항상 handle 반환)
-- =============================================================


-- ─────────────────────────────────────────────────────────────
-- §A. search_entities() 개정
-- ─────────────────────────────────────────────────────────────

DROP FUNCTION IF EXISTS search_entities(text,text,text,text,boolean,text,float8,float8,text,int,int,text,text,text,text,text,text,text,text);

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
  p_l1_node      text    DEFAULT NULL,
  p_l2_node      text    DEFAULT NULL,
  p_primary_guid text    DEFAULT NULL,
  p_handle       text    DEFAULT NULL,   -- @닉네임#태그 직접 검색 (§17.4)
  p_nickname     text    DEFAULT NULL,   -- 닉네임 검색
  p_lang_code    text    DEFAULT 'ko',   -- BCP 47 언어 코드 (§16.2)
  p_l3_node      text    DEFAULT NULL    -- 광역 노드 필터 (§13.5)
)
RETURNS TABLE (
  guid         text, primary_guid text, current_ipv6 text, l1_node text,
  entity_type  text, name text, occupation text, services text[],
  address      text, website text, is_public boolean, extra jsonb,
  trust_level  text, gdc_accepted boolean,
  rating_avg   numeric, review_count integer,
  lat numeric, lng numeric, distance_km double precision,
  handle       text, verified boolean, issuer_guid text, lang_code text
)
LANGUAGE sql STABLE AS $$
  WITH trust_order AS (
    SELECT 'L0'::text AS lvl, 0 AS ord UNION ALL
    SELECT 'L1',1 UNION ALL SELECT 'L2',2 UNION ALL SELECT 'L3',3
  )
  SELECT
    up.guid, up.primary_guid, up.current_ipv6, up.l1_node,
    up.entity_type, up.name, up.occupation, up.services,
    up.address, up.website, up.is_public, up.extra,
    COALESCE(utl.trust_level,'L0'),
    COALESCE(ugs.gdc_accepted, false),
    COALESCE(sr.weighted_avg, 0)::numeric,
    COALESCE(sr.review_count, 0)::integer,
    ll.lat, ll.lng,
    CASE
      WHEN p_lat IS NOT NULL AND p_lng IS NOT NULL AND ll.lat IS NOT NULL
      THEN 2.0*6371.0*asin(sqrt(
             power(sin(radians(ll.lat-p_lat)/2.0),2)+
             cos(radians(p_lat))*cos(radians(ll.lat))*
             power(sin(radians(ll.lng-p_lng)/2.0),2)))
      ELSE NULL
    END,
    -- nickname_cache LATERAL JOIN — 항상 handle/verified 반환 (§17.2)
    nc.handle,
    nc.verified,
    nc.issuer_guid,
    COALESCE(nc.lang_code, p_lang_code)
  FROM user_profiles up
  JOIN users u ON up.guid = u.guid
  LEFT JOIN user_trust_levels utl ON utl.guid = up.guid
  LEFT JOIN trust_order to_ ON to_.lvl = COALESCE(utl.trust_level,'L0')
  LEFT JOIN user_gdc_settings ugs ON ugs.guid = up.guid
  LEFT JOIN seller_ratings sr ON sr.seller_guid = up.guid
  LEFT JOIN LATERAL (
    SELECT lat, lng, address FROM location_log
    WHERE user_guid = up.guid ORDER BY recorded_at DESC LIMIT 1
  ) ll ON TRUE
  -- nickname_cache 항상 조인: 언어 일치 우선, verified 우선 (§17.3)
  LEFT JOIN LATERAL (
    SELECT nc2.handle, nc2.verified, nc2.issuer_guid, nc2.lang_code
    FROM   nickname_cache nc2
    WHERE  nc2.primary_guid = up.primary_guid
    ORDER BY
      (nc2.lang_code = COALESCE(p_lang_code,'ko')) DESC,
      nc2.verified DESC,
      nc2.updated_at DESC
    LIMIT 1
  ) nc ON TRUE
  WHERE
    up.is_public = TRUE
    AND (p_exclude_guid IS NULL OR up.guid          <> p_exclude_guid)
    AND (p_entity_type  IS NULL OR up.entity_type    = p_entity_type)
    AND (p_occupation   IS NULL OR up.occupation    ILIKE '%'||p_occupation||'%')
    AND (p_address      IS NULL
         OR up.address  ILIKE '%'||p_address||'%'
         OR ll.address  ILIKE '%'||p_address||'%')
    AND (p_gdc_only = FALSE OR ugs.gdc_accepted = TRUE)
    AND (p_trust_min IS NULL
         OR COALESCE(to_.ord,0) >= (SELECT ord FROM trust_order WHERE lvl=p_trust_min))
    AND (p_keyword  IS NULL
         OR up.name       ILIKE '%'||p_keyword||'%'
         OR up.occupation ILIKE '%'||p_keyword||'%'
         OR EXISTS (SELECT 1 FROM unnest(up.services) s WHERE s ILIKE '%'||p_keyword||'%'))
    AND (p_handle       IS NULL OR nc.handle      = p_handle)
    AND (p_nickname     IS NULL OR up.name        ILIKE '%'||p_nickname||'%')
    AND (p_l1_node      IS NULL OR up.l1_node      = p_l1_node)
    AND (p_l2_node      IS NULL OR up.l2_node      = p_l2_node)
    AND (p_l3_node      IS NULL OR up.l3_node      = p_l3_node)
    AND (p_primary_guid IS NULL OR up.primary_guid = p_primary_guid)
  ORDER BY
    CASE WHEN p_sort='distance' AND p_lat IS NOT NULL AND p_lng IS NOT NULL AND ll.lat IS NOT NULL
         THEN 2.0*6371.0*asin(sqrt(
                power(sin(radians(ll.lat-p_lat)/2.0),2)+
                cos(radians(p_lat))*cos(radians(ll.lat))*
                power(sin(radians(ll.lng-p_lng)/2.0),2)))
    END ASC NULLS LAST,
    CASE WHEN p_sort='rating'       THEN COALESCE(sr.weighted_avg,0) END DESC NULLS LAST,
    CASE WHEN p_sort='review_count' THEN COALESCE(sr.review_count,0) END DESC NULLS LAST,
    nc.verified DESC NULLS LAST,
    COALESCE(to_.ord,0) DESC
  LIMIT p_limit OFFSET p_offset;
$$;

COMMENT ON FUNCTION search_entities IS
  'v2.2 — §16 언어코드 닉네임 해시, §17 중복닉네임(handle), §13 지역필터, nickname_cache LATERAL JOIN';


-- ─────────────────────────────────────────────────────────────
-- §B. search_by_attributes() 신규 생성 (§14 AIS)
-- ─────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION search_by_attributes(
  p_attr_type      text     DEFAULT NULL,
  p_school_guid    text     DEFAULT NULL,
  p_enroll_from    integer  DEFAULT NULL,
  p_enroll_to      integer  DEFAULT NULL,
  p_field          text     DEFAULT NULL,
  p_l3_node        text     DEFAULT NULL,
  p_guid_list      text[]   DEFAULT NULL,
  p_limit          int      DEFAULT 50,
  p_offset         int      DEFAULT 0
)
RETURNS TABLE (
  primary_guid  text, current_ipv6 text,
  attr_type     text, school_guid text,
  enroll_year   integer, graduate_year integer,
  field         text, attr_l3_node text,
  is_public     boolean, submitted_at timestamptz
)
LANGUAGE sql STABLE AS $$
  SELECT
    ua.primary_guid, ua.current_ipv6,
    ua.attr_type, ua.school_guid,
    ua.enroll_year, ua.graduate_year,
    ua.field, ua.attr_l3_node,
    ua.is_public, ua.submitted_at
  FROM user_attributes ua
  WHERE
    ua.is_active   = TRUE
    AND ua.is_public = TRUE
    AND (p_guid_list   IS NULL OR ua.primary_guid = ANY(p_guid_list))
    AND (p_attr_type   IS NULL OR ua.attr_type    = p_attr_type)
    AND (p_school_guid IS NULL OR ua.school_guid  = p_school_guid)
    AND (p_enroll_from IS NULL OR ua.enroll_year >= p_enroll_from)
    AND (p_enroll_to   IS NULL OR ua.enroll_year <= p_enroll_to)
    AND (p_field       IS NULL OR ua.field         = p_field)
    AND (p_l3_node     IS NULL OR ua.attr_l3_node  = p_l3_node)
  ORDER BY ua.submitted_at DESC
  LIMIT p_limit OFFSET p_offset;
$$;

COMMENT ON FUNCTION search_by_attributes IS
  'v2.2 — §14 AIS 속성 인덱스 쿼리. search_entities() 1단계 결과에 2단계 필터로 연결';

DO $$
BEGIN
  RAISE NOTICE '=== Step 2 완료 (최종) ===';
  RAISE NOTICE 'search_entities(): nickname_cache LATERAL JOIN 방식으로 handle/verified 항상 반환';
  RAISE NOTICE 'search_by_attributes(): 신규 생성';
END $$;
