-- UGC CONTENT REPORTING — ptn_reports
-- Required for Google Play's user-generated-content marketplace policy:
-- buyers can flag a shop, listing, or seller content for review.
--
-- DO NOT auto-run. Peter applies via Supabase MCP (established pattern,
-- same as 20260519_dozie_order_rpcs.sql). Idempotent / self-sufficient.
--
-- Buyer flow: PARTENAIRE_Buyer.html submitReport() → POST /api/ptn_reports
-- (anon key via the server proxy) + a ptn_notifications row (type='report')
-- so admin is alerted. Mirrors the existing ptn_disputes pattern.

CREATE TABLE IF NOT EXISTS public.ptn_reports (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_type   text NOT NULL,                 -- 'shop' | 'listing' | 'seller' | 'content'
  target_id     text,                          -- shop id / product id / etc (nullable)
  target_label  text,                          -- human label for admin triage
  reason        text NOT NULL,
  description   text,
  reporter_id   uuid,                           -- ptn_users.id of the reporter (nullable)
  reporter_name text,
  status        text NOT NULL DEFAULT 'open',  -- open | reviewing | actioned | dismissed
  admin_note    text,
  reviewed_by   text,                           -- admin email (matches ptn_disputes.resolved_by)
  reviewed_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Guards for re-run on an existing table.
ALTER TABLE public.ptn_reports ADD COLUMN IF NOT EXISTS target_label  text;
ALTER TABLE public.ptn_reports ADD COLUMN IF NOT EXISTS reporter_name text;
ALTER TABLE public.ptn_reports ADD COLUMN IF NOT EXISTS admin_note    text;
ALTER TABLE public.ptn_reports ADD COLUMN IF NOT EXISTS reviewed_by   text;
ALTER TABLE public.ptn_reports ADD COLUMN IF NOT EXISTS reviewed_at   timestamptz;

CREATE INDEX IF NOT EXISTS ptn_reports_status_idx     ON public.ptn_reports (status);
CREATE INDEX IF NOT EXISTS ptn_reports_target_idx     ON public.ptn_reports (target_type, target_id);
CREATE INDEX IF NOT EXISTS ptn_reports_created_at_idx ON public.ptn_reports (created_at DESC);

-- RLS — mirror ptn_disputes. The whole app reaches Supabase through the
-- server's /api proxy using the ANON key (SUPABASE_KEY), so for the buyer
-- to FILE a report and the admin portal to READ/MODERATE it, anon needs
-- INSERT + SELECT + UPDATE — exactly as ptn_disputes is already exposed.
--
-- SECURITY NOTE: this matches the app's current anon-key posture and is no
-- looser than ptn_disputes. When the broader "anon lockdown" lands (the
-- server already has DOZIE_SERVICE_KEY for privileged reads), tighten this
-- to: anon INSERT only, and move admin SELECT/UPDATE behind the service key.
ALTER TABLE public.ptn_reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ptn_reports_insert_any ON public.ptn_reports;
CREATE POLICY ptn_reports_insert_any
  ON public.ptn_reports FOR INSERT
  TO anon, authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS ptn_reports_select_any ON public.ptn_reports;
CREATE POLICY ptn_reports_select_any
  ON public.ptn_reports FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS ptn_reports_update_any ON public.ptn_reports;
CREATE POLICY ptn_reports_update_any
  ON public.ptn_reports FOR UPDATE
  TO anon, authenticated
  USING (true) WITH CHECK (true);
