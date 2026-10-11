-- STAGING ONLY — bring staging to parity with PROD for the seller-payout feature.
-- Prod already has all of this (it was applied there directly and never committed);
-- reconstructed 2026-10-11 from prod's catalog. Additive and idempotent. Do NOT
-- apply to prod (nothing would change, but there is no reason to).

ALTER TABLE public.ptn_orders
  ADD COLUMN IF NOT EXISTS escrow_released_at   timestamptz,
  ADD COLUMN IF NOT EXISTS escrow_release_reason text,
  ADD COLUMN IF NOT EXISTS flw_payout_status    text,
  ADD COLUMN IF NOT EXISTS flw_payout_ref       text,
  ADD COLUMN IF NOT EXISTS flw_payout_id        text,
  ADD COLUMN IF NOT EXISTS flw_payout_amount    numeric,
  ADD COLUMN IF NOT EXISTS flw_payout_fee       numeric,
  ADD COLUMN IF NOT EXISTS flw_payout_at        timestamptz,
  ADD COLUMN IF NOT EXISTS flw_payout_error     text,
  ADD COLUMN IF NOT EXISTS flw_payout_attempts  integer DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS ptn_orders_flw_payout_ref_uidx ON public.ptn_orders (flw_payout_ref) WHERE flw_payout_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.ptn_seller_payout (
  user_id        uuid PRIMARY KEY REFERENCES public.ptn_users(id) ON DELETE CASCADE,
  country        text NOT NULL CONSTRAINT ptn_seller_payout_country_chk CHECK (country = ANY (ARRAY['NG','CM'])),
  method         text NOT NULL CONSTRAINT ptn_seller_payout_method_chk  CHECK (method  = ANY (ARRAY['bank','momo'])),
  bank_code      text, bank_name text, account_number text, account_name text,
  momo_number    text, momo_operator text,
  verified       boolean NOT NULL DEFAULT false,
  verified_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.ptn_seller_payout ENABLE ROW LEVEL SECURITY;   -- no policies: service key only (as prod)
