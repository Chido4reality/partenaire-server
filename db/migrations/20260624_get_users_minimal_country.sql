-- 20260624_get_users_minimal_country.sql
-- DISPLAY-ONLY currency localization support for the buyer client.
--
-- get_users_minimal (used by the buyer's loadOrders to resolve each order's
-- seller name) now ALSO returns the seller's org-derived country_code — the
-- SAME resolution as list_public_sellers / resolveOrderCurrency (the seller's
-- linked MP org country). The buyer client maps it to a currency (NG->NGN,
-- CM/other->XAF) so an order's amount + pay labels render in the right currency
-- (₦ + a neutral online label for Nigeria; FCFA + Mobile Money for Cameroon).
--
-- Additive + read-only: existing fields unchanged; other callers ignore the new
-- field. No data is mutated.

CREATE OR REPLACE FUNCTION public.get_users_minimal(p_caller uuid, p_ids uuid[])
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE c ptn_users%ROWTYPE;
BEGIN
  c := _dozie_caller(p_caller);
  IF c.id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'forbidden');
  END IF;

  RETURN jsonb_build_object('ok', true, 'users', coalesce((
    SELECT jsonb_agg(jsonb_build_object(
      'id', u.id, 'name', u.name, 'company', u.company,
      'phone', u.phone, 'profile_photo', u.profile_photo,
      -- DOZIE-ORDER-CURRENCY: org-derived shop country (mirrors
      -- list_public_sellers / resolveOrderCurrency). CM/Cameroun -> CM,
      -- NG/Nigeria -> NG, else NULL (standalone/unresolvable).
      'country_code', (
        SELECT CASE
          WHEN upper(coalesce(o.country,'')) IN ('CM','CMR','CAMEROON','CAMEROUN') THEN 'CM'
          WHEN upper(coalesce(o.country,'')) IN ('NG','NGA','NIGERIA') THEN 'NG'
          ELSE NULL END
        FROM pa_organisations o WHERE o.id = u.linked_mp_org_id
      )
    ))
    FROM ptn_users u
    WHERE u.id = ANY(p_ids)
  ), '[]'::jsonb));
END;
$function$;
