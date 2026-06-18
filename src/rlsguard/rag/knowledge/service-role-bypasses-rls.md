---
title: The service_role key bypasses Row Level Security
url: https://supabase.com/docs/guides/api/api-keys#what-secret-keys-allow-access-to
rule_ids: SUPA-KEY-001, SUPA-FUNC-001
---
Row Level Security is the boundary that makes it safe to talk to Supabase from a
browser. The catch is that some principals are exempt from it. The `service_role`
key (and the newer `sb_secret_` keys) connect as a role that is marked
`BYPASSRLS`, so policies are never evaluated for those requests - they can read
and write every row in every table.

This is why a leaked service_role key is equivalent to handing out your database:
no amount of careful policy writing protects data once a caller can bypass RLS.
The same property explains why `SECURITY DEFINER` functions deserve scrutiny - a
function owned by a privileged role runs with that role's rights and can read or
modify data the calling user could never reach directly. Use the service_role key
only on a trusted server, never in client code, and keep SECURITY DEFINER
functions minimal, search-path-pinned, and execute-restricted.
