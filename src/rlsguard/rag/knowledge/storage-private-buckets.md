---
title: Private vs public Storage buckets
url: https://supabase.com/docs/guides/storage/buckets/fundamentals
rule_ids: SUPA-STORAGE-001
---
A Supabase Storage bucket is either public or private. A public bucket serves
every object through an unauthenticated URL with no RLS check at all - anyone who
knows or guesses the path can download the file. This is fine for assets meant to
be public (avatars, marketing images) but wrong for anything per-user or
sensitive. Marking a bucket public is the most common cause of an accidental file
leak.

A private bucket routes every read and write through RLS policies on
`storage.objects`, so access control is only as good as those policies. The
canonical per-user pattern stores each user's files under a folder named for their
id and checks the first path segment:
`(storage.foldername(name))[1] = auth.uid()::text`. Choosing a private bucket and
checking ownership - not just `bucket_id` - is what keeps one user from reaching
another user's files. Apply the ownership check to writes (INSERT/UPDATE/DELETE)
as well as reads.
