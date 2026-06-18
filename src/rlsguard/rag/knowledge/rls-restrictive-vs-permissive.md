---
title: Permissive vs restrictive RLS policies
url: https://supabase.com/docs/guides/database/postgres/row-level-security#policies
rule_ids: SUPA-RLS-003, SUPA-RLS-005
---
PostgreSQL policies are PERMISSIVE by default. When several permissive policies
apply to the same command, their conditions are combined with OR: a row is
accessible if *any* one policy allows it. This is why adding a broad policy such
as `using (true)` is dangerous even when stricter policies already exist - the
permissive `true` policy widens access rather than narrowing it, and the stricter
policies no longer constrain anything.

A RESTRICTIVE policy (declared `as restrictive`) is combined with AND instead, so
it can only ever remove access. Restrictive policies are useful as a safety net -
for example, a restrictive policy requiring `auth.uid() is not null` on top of
permissive per-table policies. The key rule: to *grant* access use a narrow
permissive policy scoped to the row owner; to *guarantee* a condition always
holds, add a restrictive policy. Never rely on a permissive `using (true)` policy
to gate access to per-user or sensitive data.
