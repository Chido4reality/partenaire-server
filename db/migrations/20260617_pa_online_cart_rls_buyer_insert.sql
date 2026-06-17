-- 20260617_pa_online_cart_rls_buyer_insert.sql
--
-- FIX: "new row violates row-level security policy for table 'pa_online_cart'"
-- on the buyer Order-Placed step (live prod, e.g. ORD-686562-b093).
--
-- Partenaire uses its OWN phone-based auth, NOT Supabase Auth, so auth.uid()
-- is NULL on marketplace requests. The Dozie web server (partenaire_server.js)
-- reaches Supabase with the ANON key (supaRequest, SUPABASE_KEY) and scopes
-- rows in application code, NOT in RLS. pa_online_cart had RLS ENABLED but
-- ONLY a SELECT policy (pa_online_cart_anon_read), so the anon-key INSERT the
-- buyer flow performs had no permissive policy and was denied.
--
-- Mirror the PROVEN sibling pattern already in use for the buyer flow:
--   ptn_orders  → anon INSERT/SELECT/UPDATE/DELETE, USING/WITH CHECK true
--   ptn_messages→ anon ALL, USING/WITH CHECK true
-- i.e. RLS enabled + permissive anon policies; per-buyer/org scoping is
-- enforced by the Node server, which is the only viable model under this
-- keyless (no auth.uid()) setup. We deliberately do NOT disable RLS, do NOT
-- switch the call to service_role, and do NOT invent an auth.uid()-based
-- policy that would reject every insert.
--
-- Idempotent (DROP POLICY IF EXISTS). SELECT policy is left as-is.

ALTER TABLE pa_online_cart ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pa_online_cart_anon_insert ON pa_online_cart;
CREATE POLICY pa_online_cart_anon_insert ON pa_online_cart
  FOR INSERT TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS pa_online_cart_anon_update ON pa_online_cart;
CREATE POLICY pa_online_cart_anon_update ON pa_online_cart
  FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS pa_online_cart_anon_delete ON pa_online_cart;
CREATE POLICY pa_online_cart_anon_delete ON pa_online_cart
  FOR DELETE TO anon, authenticated USING (true);
