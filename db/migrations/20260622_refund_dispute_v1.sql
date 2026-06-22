-- DOZIE REFUND / DISPUTE RESOLUTION v1 — additive, dormant, safe.
--
-- Adds the refund bookkeeping columns to ptn_orders and widens the status
-- allowlist to include 'refunded'. payment_status and dispute_status have NO
-- CHECK constraint (free text), so 'refunded' / 'open' / 'seller_contested' /
-- 'resolved' need no constraint change. The whole refund/dispute money path is
-- gated behind PAYMENTS_ENABLED in code; with payments OFF + 0 flutterwave
-- orders these columns are simply unused.
--
-- Full-order refunds only: refund_amount always = order.total.

ALTER TABLE public.ptn_orders
  ADD COLUMN IF NOT EXISTS refund_status    text DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS refund_amount    numeric,
  ADD COLUMN IF NOT EXISTS refunded_at      timestamptz,
  ADD COLUMN IF NOT EXISTS refund_reference text;

-- Widen status to allow the terminal 'refunded' state.
ALTER TABLE public.ptn_orders DROP CONSTRAINT IF EXISTS ptn_orders_status_check;
ALTER TABLE public.ptn_orders ADD CONSTRAINT ptn_orders_status_check
  CHECK (status = ANY (ARRAY[
    'pending'::text, 'confirmed'::text, 'shipped'::text, 'ready'::text,
    'delivered'::text, 'rejected'::text, 'cancelled'::text, 'refunded'::text]));

-- Constrain the new refund_status column.
ALTER TABLE public.ptn_orders DROP CONSTRAINT IF EXISTS ptn_orders_refund_status_check;
ALTER TABLE public.ptn_orders ADD CONSTRAINT ptn_orders_refund_status_check
  CHECK (refund_status = ANY (ARRAY[
    'none'::text, 'pending_manual'::text, 'refunded'::text, 'failed'::text]));
