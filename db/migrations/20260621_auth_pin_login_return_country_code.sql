-- DOZIE-BUYER-COUNTRY: return country_code from auth_pin_login so the buyer app
-- can default the browse country filter to the logged-in buyer's own country.
-- Additive (one extra field in the returned user jsonb). Applied to prod
-- 2026-06-21. (list_public_sellers() already exposes each shop's country_code;
-- ptn_users.country_code is set at registration.)
CREATE OR REPLACE FUNCTION public.auth_pin_login(p_phone text, p_pin text, p_role text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  cleaned_phone text;
  rec ptn_users%ROWTYPE;
BEGIN
  cleaned_phone := regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g');

  IF cleaned_phone = '' OR coalesce(p_pin, '') = ''
     OR p_role NOT IN ('buyer','seller') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'invalid_credentials');
  END IF;

  SELECT * INTO rec FROM ptn_users
   WHERE regexp_replace(phone, '[^0-9]', '', 'g') = cleaned_phone
     AND role = p_role
   LIMIT 1;

  IF rec.id IS NULL
     OR rec.dozie_pin_hash IS NULL
     OR extensions.crypt(p_pin, rec.dozie_pin_hash) <> rec.dozie_pin_hash THEN
    RETURN jsonb_build_object('ok', false, 'error', 'invalid_credentials');
  END IF;

  IF rec.status = 'suspended' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'suspended');
  END IF;
  IF rec.status = 'banned' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'banned');
  END IF;

  UPDATE ptn_users SET last_seen = now() WHERE id = rec.id;

  RETURN jsonb_build_object('ok', true, 'user', jsonb_build_object(
    'id', rec.id, 'phone', rec.phone, 'name', rec.name,
    'company', rec.company, 'city', rec.city, 'category', rec.category,
    'role', rec.role, 'status', rec.status, 'shop_desc', rec.shop_desc,
    'badge_tier', rec.badge_tier, 'badge_status', rec.badge_status,
    'profile_photo', rec.profile_photo,
    'linked_mp_org_id', rec.linked_mp_org_id,
    'momo_phone', rec.momo_phone,
    'country_code', rec.country_code
  ));
END;
$function$;
