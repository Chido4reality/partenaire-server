-- DOZIE-CITY-CASCADE: public list of ALL ACTIVE cities for the buyer city
-- dropdown (country → ALL active cities → shop). NOT filtered by is_allowed —
-- a category-specific sell block (ptn_sell_blocks) must never drop a whole city
-- from the buyer's browse options. Country mapped Cameroun->CM, Nigeria->NG,
-- else NULL. ~127 rows (CM 61 / NG 66). Applied to prod 2026-06-21.
CREATE OR REPLACE FUNCTION public.list_public_cities()
 RETURNS TABLE(country_code text, town text)
 LANGUAGE sql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT CASE
           WHEN upper(coalesce(country,'')) IN ('CM','CMR','CAMEROON','CAMEROUN') THEN 'CM'
           WHEN upper(coalesce(country,'')) IN ('NG','NGA','NIGERIA') THEN 'NG'
           ELSE NULL END AS country_code,
         town
  FROM ptn_sell_towns
  WHERE is_active
  ORDER BY town;
$function$;
GRANT EXECUTE ON FUNCTION public.list_public_cities() TO anon, authenticated;
