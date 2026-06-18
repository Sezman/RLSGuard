"""General, per-rule help content for reporters (notably SARIF).

A :class:`Finding` carries *finding-specific* prose — it names the offending
table, policy, or file. GitHub code scanning, however, also renders a *rule*
help panel that is shared by every finding of a rule, and when it is empty the
UI shows "No rule help available."

This module is that missing piece: a deterministic registry of the *general*
explanation, remediation steps, a safe-code example, and the official Supabase
citations for each rule. It is intentionally independent of any single finding
so the same help renders whether a rule fired once or a hundred times. The RAG
layer (``--explain``) may *augment* this help with extra citations, but the
content here never depends on the LLM and never carries a decision (severity,
confidence, rule id) — those remain owned by the rules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Reference:
    """A documentation citation backing a rule's help panel."""

    title: str
    url: str

    @property
    def official(self) -> bool:
        """True when this points at the official Supabase documentation."""
        return "supabase.com" in self.url


@dataclass(frozen=True)
class RuleHelp:
    """The general, finding-independent help for a single rule."""

    name: str
    short_description: str
    full_description: str
    explanation: str
    remediation: str
    safe_example: str
    references: tuple[Reference, ...]

    def help_text(self) -> str:
        """Plain-text rule help: explanation, fix, example, and citations."""
        blocks = [
            self.full_description,
            "Why this matters:\n" + self.explanation,
            "How to fix it:\n" + self.remediation,
        ]
        if self.safe_example:
            blocks.append("Safe example:\n" + self.safe_example)
        if self.references:
            refs = "\n".join(f"- {r.title}: {r.url}" for r in self.references)
            blocks.append("References:\n" + refs)
        return "\n\n".join(blocks).strip()

    def help_markdown(self) -> str:
        """Markdown rule help, rendered by GitHub's code-scanning UI."""
        blocks = [
            self.full_description,
            "## Why this matters\n\n" + self.explanation,
            "## How to fix it\n\n" + self.remediation,
        ]
        if self.safe_example:
            blocks.append("## Safe example\n\n```sql\n" + self.safe_example + "\n```")
        if self.references:
            refs = "\n".join(f"- [{r.title}]({r.url})" for r in self.references)
            blocks.append("## References\n\n" + refs)
        return "\n\n".join(blocks).strip()

    def official_references(self) -> list[Reference]:
        return [r for r in self.references if r.official]


_RLS_DOCS = "https://supabase.com/docs/guides/database/postgres/row-level-security"
_RLS_POLICIES_DOCS = _RLS_DOCS + "#policies"
_RLS_ROLES_DOCS = _RLS_DOCS + "#authenticated-and-unauthenticated-roles"
_FUNC_DOCS = "https://supabase.com/docs/guides/database/functions"
_STORAGE_DOCS = "https://supabase.com/docs/guides/storage/security/access-control"
_KEYS_DOCS = "https://supabase.com/docs/guides/api/api-keys"


RULE_HELP: dict[str, RuleHelp] = {
    "SUPA-RLS-001": RuleHelp(
        name="Table in an API-exposed schema has RLS disabled",
        short_description="Row Level Security is disabled on a table reachable "
        "through the Supabase API.",
        full_description="Tables in the `public` schema are exposed through "
        "Supabase's auto-generated API. Any client holding the anon or "
        "authenticated key can query them unless Row Level Security (RLS) "
        "restricts access.",
        explanation="With RLS disabled, every row of the table can be read and "
        "written by anyone using the anon or authenticated key, with no "
        "per-user restriction. For tables holding user or otherwise sensitive "
        "data this is a direct data-exposure risk.",
        remediation="Enable Row Level Security on the table, then add an "
        "explicit policy for each operation the application performs (SELECT, "
        "INSERT, UPDATE, DELETE), scoping each to the rows the current user is "
        "allowed to touch.",
        safe_example="alter table public.<table> enable row level security;\n\n"
        'create policy "select own rows" on public.<table>\n'
        "  for select using (auth.uid() = user_id);",
        references=(
            Reference(
                "Enabling Row Level Security and writing policies", _RLS_DOCS
            ),
        ),
    ),
    "SUPA-RLS-002": RuleHelp(
        name="Table has RLS enabled but no policies",
        short_description="RLS is enabled but no policies are defined, so "
        "Postgres denies all API access to the table.",
        full_description="Enabling RLS alone denies all access: PostgreSQL "
        "applies a default-deny, so until policies exist no rows are returned "
        "to the anon or authenticated roles.",
        explanation="This is most likely to break the feature that reads the "
        "table rather than to expose data, but it means no intended access "
        "path is defined. Each operation the application performs needs its own "
        "policy.",
        remediation="Add an explicit policy for each operation the application "
        "performs, scoping each to the rows the current user may access.",
        safe_example='create policy "select own rows" on public.<table>\n'
        "  for select using (auth.uid() = user_id);",
        references=(
            Reference(
                "Enabling Row Level Security and writing policies", _RLS_DOCS
            ),
        ),
    ),
    "SUPA-RLS-003": RuleHelp(
        name="Policy uses an unrestricted (USING true) expression",
        short_description="A policy expression is simply `true`, placing no "
        "restriction on the rows it applies to.",
        full_description="A policy whose expression is simply `true` places no "
        "restriction on the rows it applies to. `USING (true)` on a SELECT "
        "policy exposes every row to any anon or authenticated client; "
        "`WITH CHECK (true)` on a write lets a client write arbitrary rows.",
        explanation="This is occasionally intentional (genuinely public data) "
        "but is frequently a mistake on tables that hold per-user or sensitive "
        "information. Treat unrestricted write policies "
        "(INSERT/UPDATE/DELETE/ALL) as high risk, since they let any permitted "
        "role modify rows they do not own.",
        remediation="Replace the `true` expression with a condition that ties "
        "access to the current user. If the table really is meant to be "
        "world-readable, confirm every column is safe to expose first.",
        safe_example='create policy "select own rows" on public.<table>\n'
        "  for select using (auth.uid() = user_id);",
        references=(
            Reference(
                "Avoid unrestricted (USING true) policies", _RLS_POLICIES_DOCS
            ),
        ),
    ),
    "SUPA-RLS-004": RuleHelp(
        name="UPDATE policy has no explicit WITH CHECK",
        short_description="An UPDATE policy defines USING but omits an explicit "
        "WITH CHECK clause (hardening).",
        full_description="An UPDATE policy has two expressions: USING decides "
        "which existing rows a user may update, and WITH CHECK validates the "
        "new row values. When WITH CHECK is omitted, PostgreSQL reuses the "
        "USING expression as the implicit check, so this is not by itself a "
        "vulnerability.",
        explanation="Relying on the implicit fallback is fragile. Defining "
        "WITH CHECK explicitly stops a user from moving a row outside their own "
        "scope (for example reassigning ownership) and keeps the policy correct "
        "if USING is later changed.",
        remediation="Add an explicit WITH CHECK, typically matching USING.",
        safe_example='create policy "update own profile" on public.profiles\n'
        "  for update\n"
        "  using (auth.uid() = id)\n"
        "  with check (auth.uid() = id);",
        references=(
            Reference(
                "UPDATE policies need both USING and WITH CHECK",
                _RLS_POLICIES_DOCS,
            ),
        ),
    ),
    "SUPA-RLS-005": RuleHelp(
        name="Policy on an owned table does not scope to the owner",
        short_description="A policy on a table with an ownership column does "
        "not restrict access to the row's owner.",
        full_description="In a multi-tenant application rows usually belong to "
        "a user, identified by a column such as `user_id`, `owner_id`, "
        "`created_by`, `author_id`, or `account_id` — often a foreign key to "
        "`auth.users`. To restrict access to the owner, a policy must compare "
        "`auth.uid()` to that ownership column.",
        explanation="A policy that does not reference both `auth.uid()` and the "
        "ownership column may let a user reach other users' rows — for example "
        "a read policy that only checks `auth.role() = 'authenticated'`, or one "
        "that compares `auth.uid()` to the wrong column. A deliberately shared "
        "or public feed can be a legitimate exception, so review the intent.",
        remediation="Scope the policy to the row owner by comparing "
        "`auth.uid()` to the ownership column.",
        safe_example='create policy "select own rows" on public.<table>\n'
        "  for select using (auth.uid() = user_id);",
        references=(
            Reference(
                "Scope policies to the row owner with auth.uid()",
                _RLS_ROLES_DOCS,
            ),
        ),
    ),
    "SUPA-FUNC-001": RuleHelp(
        name="SECURITY DEFINER function requires review",
        short_description="A function declared SECURITY DEFINER runs with its "
        "owner's privileges and can bypass RLS.",
        full_description="A function declared SECURITY DEFINER runs with the "
        "privileges of the function's owner (often a highly privileged role) "
        "rather than the caller, and it can bypass Row Level Security. This is "
        "sometimes necessary, but each such function needs review to ensure it "
        "cannot be abused to escalate privileges or read data the caller should "
        "not see.",
        explanation="Risk rises when the function has no pinned `search_path` "
        "(schema-injection risk), uses dynamic SQL, modifies data, or runs with "
        "no visible authorization check while being callable through the API.",
        remediation="Pin the search path, restrict who may execute the "
        "function, add explicit authorization checks inside it, and avoid "
        "dynamic SQL (or use `format()` with `%I`/`%L` and validate inputs).",
        safe_example="alter function public.<fn> set search_path = '';\n"
        "revoke execute on function public.<fn> from public;\n"
        "grant execute on function public.<fn> to authenticated;",
        references=(
            Reference("Hardening SECURITY DEFINER functions", _FUNC_DOCS),
        ),
    ),
    "SUPA-STORAGE-001": RuleHelp(
        name="Storage policy does not verify file ownership",
        short_description="A storage.objects policy gates on the bucket but not "
        "on which user owns the file.",
        full_description="Supabase Storage enforces access through RLS policies "
        "on the `storage.objects` table. A policy that checks only `bucket_id` "
        "lets every permitted user reach every file in that bucket — fine for a "
        "deliberately public bucket, but a leak for per-user private files.",
        explanation="Without an ownership check, any role the policy applies to "
        "can read (or, for write policies, overwrite and delete) every file in "
        "the bucket, not just their own.",
        remediation="Scope access to the file's owner by storing each user's "
        "files under a folder named for their user id and checking the first "
        "path segment with `storage.foldername`. Apply the same check to write "
        "operations.",
        safe_example='create policy "read own files" on storage.objects\n'
        "  for select using (\n"
        "    bucket_id = 'private-documents'\n"
        "    and (storage.foldername(name))[1] = auth.uid()::text\n"
        "  );",
        references=(
            Reference(
                "Storage access control — verify ownership, not just the bucket",
                _STORAGE_DOCS,
            ),
        ),
    ),
    "SUPA-KEY-001": RuleHelp(
        name="Privileged Supabase credential exposed",
        short_description="A service_role key, database password, or other "
        "privileged secret was found in client-accessible or committed code.",
        full_description="Supabase projects have a publishable (anon) key, "
        "designed to ship in client code and constrained by RLS, and a secret "
        "(service_role) key. The service_role key and newer `sb_secret_` keys "
        "bypass RLS entirely and have full read/write access to the database.",
        explanation="If a service_role key, database password, JWT secret, or "
        "Postgres connection string leaks into client code or a committed "
        "`.env` file, anyone can read and modify all of your data regardless of "
        "RLS. These secrets must stay server-side only.",
        remediation="Remove the secret and rotate it immediately in the "
        "Supabase dashboard — treat the old value as compromised. Load it only "
        "from a server-side environment variable, ensure `.env` files are in "
        "`.gitignore`, and use the publishable/anon key in the client.",
        safe_example="# server-side only, never bundled into the client\n"
        "const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);",
        references=(
            Reference(
                "Supabase API keys — keep the service_role key secret",
                _KEYS_DOCS,
            ),
        ),
    ),
}


def get_rule_help(rule_id: str, *, fallback_references: list[str] | None = None) -> RuleHelp:
    """Return the registered help for ``rule_id``.

    A rule with no registered entry still gets usable (if generic) help so the
    SARIF panel is never empty — its references come from ``fallback_references``
    (typically the finding's own ``references`` list).
    """
    help_ = RULE_HELP.get(rule_id)
    if help_ is not None:
        return help_

    refs = tuple(
        Reference(url, url) for url in (fallback_references or []) if url
    )
    generic = (
        "Review this finding against the linked Supabase documentation and "
        "apply the recommended access controls."
    )
    return RuleHelp(
        name=rule_id,
        short_description=generic,
        full_description=generic,
        explanation=generic,
        remediation="See the referenced Supabase documentation.",
        safe_example="",
        references=refs,
    )
