---
title: Publishable vs secret Supabase API keys
url: https://supabase.com/docs/guides/api/api-keys
rule_ids: SUPA-KEY-001
---
Supabase is moving from the legacy JWT-based keys (`anon` and `service_role`) to
a new key format. The publishable key (prefix `sb_publishable_`) replaces the
anon key: it is safe to ship in client code because every request it makes is
still constrained by Row Level Security. The secret key (prefix `sb_secret_`)
replaces the service_role key: it bypasses RLS and grants full read/write access.

Telling them apart matters. A `sb_publishable_` key or an anon JWT (its payload
has `"role": "anon"`) in client code is expected and safe. A `sb_secret_` key, a
service_role JWT (`"role": "service_role"`), a database password, or a JWT
signing secret in client-accessible code or a committed `.env` file is a serious
exposure: anyone who extracts it can read and modify all data regardless of RLS.
Keep secret keys server-side only, loaded from environment variables, and rotate
any that have leaked.
