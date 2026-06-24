-- 20260624_list_public_sellers_country_parity.sql
-- PARITY/idempotent: the buyer browse/cart/QOF currency localization reads each
-- shop's country_code from the list_public_sellers payload. PROD already returns
-- it (org-derived); STAGING (ybsqwmtcpxjbybcbisbq) was behind and returned NULL.
-- This CREATE OR REPLACE restores parity (no-op on prod). Same org-derivation as
-- get_users_minimal / resolveOrderCurrency.

CREATE OR REPLACE FUNCTION public.list_public_sellers()
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
  SELECT coalesce(jsonb_agg(s.row_data ORDER BY
    s.featured DESC NULLS LAST,
    s.featured_order ASC NULLS LAST,
    s.created_at DESC
  ), '[]'::jsonb)
  FROM (
    SELECT u.featured, u.featured_order, u.created_at,
      jsonb_build_object(
        'id', u.id, 'name', u.name, 'company', u.company, 'city', u.city,
        'category', u.category, 'profile_photo', u.profile_photo,
        'shop_desc', u.shop_desc,
        'badge_tier', u.badge_tier, 'badge_status', u.badge_status,
        'featured', u.featured, 'featured_order', u.featured_order,
        'featured_label', u.featured_label,
        'avg_rating', u.avg_rating, 'review_count', u.review_count,
        'country_code', (
          SELECT CASE
            WHEN upper(coalesce(o.country,'')) IN ('CM','CMR','CAMEROON','CAMEROUN') THEN 'CM'
            WHEN upper(coalesce(o.country,'')) IN ('NG','NGA','NIGERIA') THEN 'NG'
            ELSE NULL END
          FROM pa_organisations o WHERE o.id = u.linked_mp_org_id
        ),
        'has_premium_perks', EXISTS(
          SELECT 1 FROM ptn_standalone_subs ss
          WHERE ss.seller_id = u.id
            AND ss.tier = 'paid_standalone' AND ss.status = 'active'
        )
      ) AS row_data
    FROM ptn_users u
    WHERE u.role = 'seller' AND u.status = 'active'
  ) s;
$function$;
