-- DOZIE REFUND / DISPUTE v1 — ATOMIC dual-write RPCs + ptn_disputes write lockdown.
--
-- (1) The dispute/refund state lives in TWO places that must never drift: the
--     authoritative ptn_disputes row (seller Litiges + admin) and the inline
--     ptn_orders dispute cols (buyer display + payout interlock + refund guards).
--     Each transition is a SECURITY DEFINER RPC that writes BOTH in ONE
--     transaction (same drift-class we fixed on customer total_debt). FOR UPDATE
--     on the order row serialises concurrent calls → idempotent, no double refund.
--
-- (2) EXECUTE is REVOKED from public/anon and granted ONLY to service_role: the
--     Dozie + MP servers call these via the service role AFTER authenticating the
--     buyer/seller/admin. The anon key can never call them to forge state.
--
-- (3) ptn_disputes write lockdown: drop the blanket anon insert/update/delete
--     policies + revoke anon/authenticated INSERT/UPDATE/DELETE. All writers are
--     now server-side (buyer raise + seller reply/approve/contest + admin). anon
--     SELECT is KEPT for now (the standalone seller Litiges view reads it
--     client-side); a SELECT-via-RPC lockdown is a flagged follow-up.
--
-- Full-order refunds only. DORMANT: nothing calls these until PAYMENTS_ENABLED.

-- Widen ptn_disputes.status to the states this flow uses. The prior allowlist was
-- ['open','resolved_refund','resolved_release','resolved_partial','closed']; add
-- 'seller_contested' + 'resolved' (this flow's vocabulary) + 'escalated' (the
-- pre-existing admin escalate route also wrote this, outside the old allowlist).
ALTER TABLE public.ptn_disputes DROP CONSTRAINT IF EXISTS ptn_disputes_status_check;
ALTER TABLE public.ptn_disputes ADD CONSTRAINT ptn_disputes_status_check
  CHECK (status = ANY (ARRAY[
    'open'::text, 'seller_contested'::text, 'escalated'::text, 'resolved'::text,
    'resolved_refund'::text, 'resolved_release'::text, 'resolved_partial'::text, 'closed'::text]));

-- ── RAISE (buyer) ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.dozie_dispute_raise(p_order_id uuid, p_buyer_id uuid, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_o ptn_orders%ROWTYPE; v_now timestamptz := now();
BEGIN
  SELECT * INTO v_o FROM ptn_orders WHERE id = p_order_id FOR UPDATE;
  IF v_o.id IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_found'); END IF;
  IF v_o.buyer_id <> p_buyer_id THEN RETURN jsonb_build_object('ok', false, 'reason', 'forbidden'); END IF;
  IF NOT (v_o.payment_method = 'flutterwave' AND v_o.payment_status = 'paid')
    THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_disputable'); END IF;
  IF v_o.status IN ('refunded', 'cancelled') OR v_o.escrow_released IS TRUE
    THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_disputable'); END IF;
  IF v_o.dispute_status IN ('open', 'seller_contested', 'escalated')
    THEN RETURN jsonb_build_object('ok', true, 'idempotent', true, 'dispute_status', v_o.dispute_status); END IF;

  UPDATE ptn_orders SET dispute_raised = true, dispute_raised_at = v_now, dispute_reason = p_reason,
    dispute_by = p_buyer_id, dispute_status = 'open', updated_at = v_now WHERE id = p_order_id;
  IF NOT EXISTS (SELECT 1 FROM ptn_disputes WHERE order_id = p_order_id AND status IN ('open', 'seller_contested', 'escalated')) THEN
    INSERT INTO ptn_disputes (order_id, order_ref, buyer_id, seller_id, buyer_claim, amount, status, created_at)
    VALUES (p_order_id, v_o.order_ref, v_o.buyer_id, v_o.seller_id, p_reason, COALESCE(v_o.total, 0), 'open', v_now);
  END IF;
  RETURN jsonb_build_object('ok', true, 'dispute_status', 'open', 'seller_id', v_o.seller_id, 'order_ref', v_o.order_ref);
END; $$;

-- ── CONTEST (seller) ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.dozie_dispute_contest(p_order_id uuid, p_seller_id uuid, p_reply text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_o ptn_orders%ROWTYPE; v_now timestamptz := now();
BEGIN
  SELECT * INTO v_o FROM ptn_orders WHERE id = p_order_id FOR UPDATE;
  IF v_o.id IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_found'); END IF;
  IF v_o.seller_id <> p_seller_id THEN RETURN jsonb_build_object('ok', false, 'reason', 'forbidden'); END IF;
  IF v_o.dispute_status <> 'open' THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_open'); END IF;

  UPDATE ptn_orders SET dispute_status = 'seller_contested', seller_dispute_reply = p_reply,
    seller_reply_at = v_now, updated_at = v_now WHERE id = p_order_id;
  UPDATE ptn_disputes SET status = 'seller_contested', seller_reply = p_reply, seller_replied_at = v_now
    WHERE order_id = p_order_id AND status = 'open';
  RETURN jsonb_build_object('ok', true, 'dispute_status', 'seller_contested', 'buyer_id', v_o.buyer_id, 'order_ref', v_o.order_ref);
END; $$;

-- ── SELLER REPLY (standalone seller portal — single table, server-side) ───────
CREATE OR REPLACE FUNCTION public.dozie_dispute_seller_reply(p_order_id uuid, p_seller_id uuid, p_reply text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_d ptn_disputes%ROWTYPE; v_now timestamptz := now();
BEGIN
  SELECT * INTO v_d FROM ptn_disputes WHERE order_id = p_order_id AND status IN ('open', 'seller_contested') ORDER BY created_at DESC LIMIT 1;
  IF v_d.id IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'no_open_dispute'); END IF;
  IF v_d.seller_id <> p_seller_id THEN RETURN jsonb_build_object('ok', false, 'reason', 'forbidden'); END IF;
  UPDATE ptn_disputes SET seller_reply = p_reply, seller_replied_at = v_now WHERE id = v_d.id;
  UPDATE ptn_orders SET seller_dispute_reply = p_reply, seller_reply_at = v_now, updated_at = v_now WHERE id = p_order_id;
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── REFUND CLAIM (atomic terminal state; reverse + FLW happen in the server) ──
CREATE OR REPLACE FUNCTION public.dozie_refund_claim(p_order_id uuid, p_by text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_o ptn_orders%ROWTYPE; v_now timestamptz := now(); v_amount numeric;
BEGIN
  SELECT * INTO v_o FROM ptn_orders WHERE id = p_order_id FOR UPDATE;
  IF v_o.id IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'order_not_found'); END IF;
  -- already terminal → idempotent. MUST come before the not_online_paid guard:
  -- once refunded, payment_status is 'refunded', so a re-claim would otherwise
  -- wrongly fall through to not_online_paid instead of an idempotent success.
  IF v_o.status = 'refunded' OR v_o.refund_status IN ('refunded', 'pending_manual')
    THEN RETURN jsonb_build_object('ok', true, 'idempotent', true, 'claimed', false, 'refund_status', v_o.refund_status); END IF;
  IF NOT (v_o.payment_method = 'flutterwave' AND v_o.payment_status = 'paid')
    THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_online_paid'); END IF;

  v_amount := COALESCE(CASE WHEN v_o.counter_status = 'accepted' THEN v_o.counter_total ELSE v_o.total END, v_o.total, 0);

  -- escrow already paid out → can't auto-claw-back; flag manual.
  IF v_o.escrow_released IS TRUE THEN
    UPDATE ptn_orders SET refund_status = 'pending_manual', refund_amount = v_amount, updated_at = v_now WHERE id = p_order_id;
    RETURN jsonb_build_object('ok', true, 'claimed', false, 'refund_status', 'pending_manual', 'note', 'escrow_already_released');
  END IF;

  -- atomic terminal claim (the FOR UPDATE lock serialises a concurrent caller,
  -- which then re-reads the refunded row and hits the idempotent branch above).
  UPDATE ptn_orders SET status = 'refunded', payment_status = 'refunded', escrow_held = 0,
    refund_status = 'pending_manual', refund_amount = v_amount,
    dispute_status = 'resolved', dispute_resolution = 'refunded', dispute_resolved_at = v_now, updated_at = v_now
    WHERE id = p_order_id;
  UPDATE ptn_disputes SET status = 'resolved', resolved_by = p_by, resolution_note = 'Refund issued', resolved_at = v_now
    WHERE order_id = p_order_id AND status IN ('open', 'seller_contested', 'escalated');
  RETURN jsonb_build_object('ok', true, 'claimed', true, 'amount', v_amount,
    'buyer_id', v_o.buyer_id, 'seller_id', v_o.seller_id, 'order_ref', v_o.order_ref);
END; $$;

-- ── REFUND MARK PAID (upgrade pending_manual → refunded after FLW confirms) ───
CREATE OR REPLACE FUNCTION public.dozie_refund_mark_paid(p_order_id uuid, p_reference text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE ptn_orders SET refund_status = 'refunded', refund_reference = p_reference, refunded_at = now(), updated_at = now()
    WHERE id = p_order_id AND refund_status = 'pending_manual';
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── REJECT (admin arbitrates a contested dispute in the seller's favour) ──────
CREATE OR REPLACE FUNCTION public.dozie_dispute_reject(p_order_id uuid, p_by text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_o ptn_orders%ROWTYPE; v_now timestamptz := now();
BEGIN
  SELECT * INTO v_o FROM ptn_orders WHERE id = p_order_id FOR UPDATE;
  IF v_o.id IS NULL THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_found'); END IF;
  IF v_o.dispute_status <> 'seller_contested' THEN RETURN jsonb_build_object('ok', false, 'reason', 'not_contested'); END IF;
  UPDATE ptn_orders SET dispute_status = 'resolved', dispute_resolution = 'rejected', dispute_resolved_at = v_now, updated_at = v_now
    WHERE id = p_order_id;
  UPDATE ptn_disputes SET status = 'resolved', resolved_by = p_by, resolution_note = 'Refund rejected by admin', resolved_at = v_now
    WHERE order_id = p_order_id AND status IN ('open', 'seller_contested', 'escalated');
  RETURN jsonb_build_object('ok', true, 'buyer_id', v_o.buyer_id, 'seller_id', v_o.seller_id, 'order_ref', v_o.order_ref);
END; $$;

-- EXECUTE: revoke from public/anon/authenticated; grant ONLY to service_role.
DO $$
DECLARE fn text;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'dozie_dispute_raise(uuid,uuid,text)', 'dozie_dispute_contest(uuid,uuid,text)',
    'dozie_dispute_seller_reply(uuid,uuid,text)', 'dozie_refund_claim(uuid,text)',
    'dozie_refund_mark_paid(uuid,text)', 'dozie_dispute_reject(uuid,text)']
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, anon, authenticated;', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO service_role;', fn);
  END LOOP;
END $$;

-- ── ptn_disputes WRITE LOCKDOWN ──────────────────────────────────────────────
-- All writers are now server-side (service role). Drop the blanket anon write
-- policies + revoke anon/authenticated write grants. KEEP anon SELECT (standalone
-- seller Litiges reads client-side) — SELECT-via-RPC lockdown is a follow-up.
DROP POLICY IF EXISTS anon_insert ON public.ptn_disputes;
DROP POLICY IF EXISTS anon_update ON public.ptn_disputes;
DROP POLICY IF EXISTS anon_delete ON public.ptn_disputes;
REVOKE INSERT, UPDATE, DELETE ON public.ptn_disputes FROM anon, authenticated;
