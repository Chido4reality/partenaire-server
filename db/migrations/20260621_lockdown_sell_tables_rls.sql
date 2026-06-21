-- SECURITY LOCKDOWN: ptn_sell_towns / ptn_sell_blocks / ptn_sell_categories are
-- ADMIN-ONLY tables (city catalog + Dozie sell block-rules). They shipped with
-- RLS DISABLED and FULL anon+authenticated privileges — anyone holding the public
-- client (anon) key could read or even WIPE them. Lock them down:
--   * ENABLE RLS with NO policies → anon/authenticated get ZERO row access.
--   * REVOKE ALL table privileges from anon + authenticated.
-- service_role retains its grants AND bypasses RLS, so the paths that legitimately
-- touch these tables keep working with NO code change:
--   * admin "Sell restrictions" panel → MP backend adminDozie.js (service_role)
--   * seller enforcement checkSellRules → MP lib/dozieSellRules.js (service_role)
--     + Dozie partenaire_server.js (supaRequestPrivileged / DOZIE_SERVICE_KEY)
--   * buyer city dropdown → list_public_cities() (SECURITY DEFINER, owner-run)
--   * shop feed → list_public_sellers() (SECURITY DEFINER)
-- Verified before applying: no client/anon path reads or writes these tables
-- directly. Applied to prod ftxttdagpioieyzaijdc 2026-06-21. Post-checks passed:
-- anon RPCs still 127 cities / shops; anon direct SELECT now 401 permission
-- denied; service writes + (moto_parts,Cameroun,Douala) enforcement intact.
ALTER TABLE public.ptn_sell_towns      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ptn_sell_blocks     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ptn_sell_categories ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.ptn_sell_towns, public.ptn_sell_blocks, public.ptn_sell_categories FROM anon, authenticated;
