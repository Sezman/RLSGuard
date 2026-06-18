---
title: Column-Level Security for sensitive columns
url: https://supabase.com/docs/guides/database/postgres/column-level-security
rule_ids: SUPA-RLS-003
---
Row Level Security decides which rows a user can see, but every column of a
visible row is returned. When a table mixes public columns with sensitive ones -
for example a `profiles` table holding a public `username` alongside a private
`email`, `phone`, or `stripe_customer_id` - an RLS policy that exposes the row
also exposes those sensitive columns.

PostgreSQL column privileges (Column-Level Security) let you grant SELECT on only
a subset of columns: `revoke select on public.profiles from authenticated;` then
`grant select (id, username) on public.profiles to authenticated;`. Combine this
with RLS rather than replacing it. Before relying on an unrestricted or broad read
policy, check whether the table holds columns that should not be world-readable,
and either split the sensitive data into a separate table protected by its own
policy or restrict access at the column level.
