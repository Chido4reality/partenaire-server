-- DOZIE-BUYER-COUNTRY: capture which country a buyer registered under (CM/NG),
-- set by /auth/register-buyer from the country selector. Additive + nullable;
-- existing buyers stay NULL (unknown, lenient). Phone normalisation is unchanged
-- (stored bare with the dial code stripped) — this column is the country source
-- for later country-aware browsing/currency. Applied to prod 2026-06-21.
ALTER TABLE public.ptn_users ADD COLUMN IF NOT EXISTS country_code text;
