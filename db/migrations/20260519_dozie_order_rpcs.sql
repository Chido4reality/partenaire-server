-- STAGE-1-DOZIE-ORDER-RPC — authenticated order creation + Campay flow.
-- DO NOT auto-run. Peter applies via Supabase MCP (established pattern).
-- All functions: SECURITY DEFINER, SET search_path = public.
--
-- Columns some RPCs set may not exist yet on older ptn_orders — guarded
-- with ADD COLUMN IF NOT EXISTS so this migration is self-sufficient and
-- idempotent (no-op if already present).
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS payment_requested      boolean;
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS payment_requested_at   timestamptz;
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS campay_reference       text;
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS campay_operator        text;
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS campay_status          text;
ALTER TABLE public.ptn_orders ADD COLUMN IF NOT EXISTS payer_phone            text;

-- ─────────────────────────────────────────────────────────────────────
-- A. ptn_create_order — server-side total recompute, single-seller,
--    60s idempotency. buyer_id is ALWAYS p_caller (JWT), never trusted
--    from the client.
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.ptn_create_order(
  p_caller       uuid,
  p_seller_id    uuid,
  p_items        jsonb,          -- [{ "product_id": uuid, "qty": int }]
  p_client_total numeric,
  p_mode         text,
  p_pay_option   text,
  p_city         text,
  p_notes        text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_server_total numeric := 0;
  v_enriched     jsonb;
  v_items_hash   text;
  v_existing     uuid;
  v_order_id     uuid;
  v_order_ref    text;
  v_bad_seller   int;
  v_prod_count   int;
  v_req_count    int;
BEGIN
  -- Caller must be a real ptn_users row.
  IF NOT EXISTS (SELECT 1 FROM ptn_users WHERE id = p_caller) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'auth_failed',
                              'message', 'Unknown caller');
  END IF;

  IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array'
     OR jsonb_array_length(p_items) = 0 THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'validation',
                              'message', 'No items');
  END IF;

  -- Resolve every line against ptn_products (current price + seller),
  -- ordered by product_id so the enriched jsonb (and its md5) is stable.
  WITH req AS (
    SELECT (i->>'product_id')::uuid AS product_id,
           GREATEST(COALESCE((i->>'qty')::int, 0), 0) AS qty
    FROM jsonb_array_elements(p_items) i
  ),
  joined AS (
    SELECT r.product_id, r.qty, pr.name, pr.price, pr.seller_id
    FROM req r
    LEFT JOIN ptn_products pr ON pr.id = r.product_id
    ORDER BY r.product_id
  )
  SELECT
    COALESCE(SUM(price * qty), 0),
    COUNT(*) FILTER (WHERE name IS NULL),
    COUNT(*),
    COUNT(*) FILTER (WHERE seller_id IS DISTINCT FROM p_seller_id),
    jsonb_agg(jsonb_build_object('product_id', product_id, 'name', name,
                                 'qty', qty, 'price', price))
  INTO v_server_total, v_prod_count, v_req_count, v_bad_seller, v_enriched
  FROM joined;

  IF v_prod_count > 0 THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'validation',
                              'message', 'One or more products no longer exist');
  END IF;

  IF v_bad_seller > 0 THEN
    RETURN jsonb_build_object('success', false,
      'error_code', 'multi_seller_in_single_order',
      'message', 'All items in one order must belong to the same seller');
  END IF;

  -- Money equality on integer-FCFA values; round to be safe.
  IF round(v_server_total, 2) <> round(COALESCE(p_client_total, -1), 2) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'price_mismatch',
      'message', 'Prices changed, please review your cart',
      'server_total', v_server_total, 'client_total', p_client_total);
  END IF;

  v_items_hash := md5(v_enriched::text);

  -- Idempotency: same buyer+seller+items, still pending, < 60s old.
  SELECT id INTO v_existing
  FROM ptn_orders
  WHERE buyer_id = p_caller
    AND seller_id = p_seller_id
    AND status = 'pending'
    AND created_at > now() - interval '60 seconds'
    AND md5(items::text) = v_items_hash
  ORDER BY created_at DESC
  LIMIT 1;

  IF v_existing IS NOT NULL THEN
    SELECT order_ref INTO v_order_ref FROM ptn_orders WHERE id = v_existing;
    RETURN jsonb_build_object('success', true, 'order_id', v_existing,
      'order_ref', v_order_ref, 'server_total', v_server_total,
      'idempotent', true);
  END IF;

  v_order_ref := 'ORD-' || to_char(now(), 'YYMMDD')
                 || upper(substring(md5(random()::text), 1, 5));

  INSERT INTO ptn_orders (
    order_ref, buyer_id, seller_id, items, total, mode, pay_option,
    deposit_paid, status, payment_status, campay_status,
    payment_requested, escrow_held, city, notes, created_at
  ) VALUES (
    v_order_ref, p_caller, p_seller_id, v_enriched, v_server_total,
    p_mode, p_pay_option, v_server_total, 'pending', 'unpaid', 'pending',
    false, v_server_total, p_city, p_notes, now()
  )
  RETURNING id INTO v_order_id;

  INSERT INTO ptn_audit_log (admin_email, action, target_type, target_id, details)
  VALUES ('system:dozie-order', 'order_created', 'ptn_orders', v_order_id,
          jsonb_build_object('buyer_id', p_caller, 'seller_id', p_seller_id,
                             'total', v_server_total, 'order_ref', v_order_ref));

  RETURN jsonb_build_object('success', true, 'order_id', v_order_id,
    'order_ref', v_order_ref, 'server_total', v_server_total);
EXCEPTION WHEN OTHERS THEN
  RETURN jsonb_build_object('success', false, 'error_code', 'validation',
    'message', SQLERRM);
END;
$$;

-- ─────────────────────────────────────────────────────────────────────
-- B. ptn_request_payment — mark an order payment-requested. Caller must
--    own the order.
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.ptn_request_payment(
  p_caller      uuid,
  p_order_id    uuid,
  p_payer_phone text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_order ptn_orders%ROWTYPE;
BEGIN
  SELECT * INTO v_order FROM ptn_orders WHERE id = p_order_id;
  IF v_order.id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'not_found',
                              'message', 'Order not found');
  END IF;
  IF v_order.buyer_id <> p_caller THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'forbidden',
                              'message', 'Not your order');
  END IF;

  UPDATE ptn_orders
     SET payment_requested = true,
         payment_requested_at = now(),
         payer_phone = COALESCE(p_payer_phone, payer_phone)
   WHERE id = p_order_id;

  RETURN jsonb_build_object('success', true,
    'order_ref', v_order.order_ref,
    'total', COALESCE(v_order.total, v_order.escrow_held),
    'payer_phone', p_payer_phone,
    'ext_reference', 'PAY-' || substring(p_order_id::text, 1, 8));
END;
$$;

-- ─────────────────────────────────────────────────────────────────────
-- C. ptn_record_campay_reference — persist the Campay collect result.
--    Caller must own the order.
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.ptn_record_campay_reference(
  p_caller           uuid,
  p_order_id         uuid,
  p_campay_reference text,
  p_campay_operator  text,
  p_campay_status    text,
  p_error_message    text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_order ptn_orders%ROWTYPE;
BEGIN
  SELECT * INTO v_order FROM ptn_orders WHERE id = p_order_id;
  IF v_order.id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'not_found',
                              'message', 'Order not found');
  END IF;
  IF v_order.buyer_id <> p_caller THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'forbidden',
                              'message', 'Not your order');
  END IF;

  UPDATE ptn_orders
     SET campay_reference = COALESCE(p_campay_reference, campay_reference),
         campay_operator  = COALESCE(p_campay_operator, campay_operator),
         campay_status    = p_campay_status,
         notes            = COALESCE(p_error_message, notes)
   WHERE id = p_order_id;

  IF p_error_message IS NULL AND p_campay_reference IS NOT NULL THEN
    INSERT INTO ptn_campay_transactions
      (order_id, reference, operator, status, amount, payer_phone)
    VALUES
      (p_order_id, p_campay_reference, p_campay_operator,
       COALESCE(p_campay_status, 'pending'),
       COALESCE(v_order.total, v_order.escrow_held), v_order.payer_phone);
  END IF;

  INSERT INTO ptn_audit_log (admin_email, action, target_type, target_id, details)
  VALUES ('system:dozie-order',
          CASE WHEN p_error_message IS NULL THEN 'campay_initiated'
               ELSE 'campay_failed' END,
          'ptn_orders', p_order_id,
          jsonb_build_object('reference', p_campay_reference,
                             'operator', p_campay_operator,
                             'status', p_campay_status,
                             'error', p_error_message));

  RETURN jsonb_build_object('success', true);
END;
$$;

-- Anon may EXECUTE (the Node backend calls these with the anon key, per
-- the M-2.1 design — auth is enforced in-app via the Dozie JWT, and the
-- RPC re-checks p_caller ownership).
GRANT EXECUTE ON FUNCTION public.ptn_create_order(uuid,uuid,jsonb,numeric,text,text,text,text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ptn_request_payment(uuid,uuid,text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ptn_record_campay_reference(uuid,uuid,text,text,text,text) TO anon, authenticated;
