---
title: How RLS policies apply to the anon and authenticated roles
url: https://supabase.com/docs/guides/database/postgres/row-level-security#authenticated-and-unauthenticated-roles
rule_ids: SUPA-RLS-001, SUPA-RLS-002
---
Every request to Supabase's auto-generated API runs as a Postgres role. A request
with no user session uses the `anon` role; a request carrying a valid user JWT
uses the `authenticated` role. Row Level Security policies are evaluated against
whichever of these roles is making the request, so a policy that is safe for one
role can still expose data to the other.

A policy can be scoped to specific roles with a `TO` clause, for example
`create policy ... on public.profiles for select to authenticated using (...)`.
A policy with no `TO` clause applies to every role, including `anon`. When you
enable RLS but write only `authenticated` policies, anonymous requests fall
through to the default-deny and see nothing - which is usually the intent for
private data. The mistake to watch for is the opposite: a broad policy with no
`TO` clause (or `to public`) that unintentionally grants the same access to
anonymous callers. Always confirm which role each policy is meant to serve.
