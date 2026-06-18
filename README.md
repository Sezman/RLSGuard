# RLSGuard

A static security scanner for **Supabase** projects. It inspects SQL migrations
and application code for the configuration and authorization mistakes that
commonly appear in AI-generated / "vibe-coded" Supabase apps — disabled Row
Level Security, overly permissive policies, exposed service-role keys, unsafe
storage rules, and risky `SECURITY DEFINER` functions.

RLSGuard runs **fully offline** — it never connects to a live Supabase project.
It reports *likely* risks with a confidence level and remediation; it never
claims an application is completely secure.

## Status

MVP rule set complete — all eight initial rules implemented and tested:

- `rlsguard scan PATH` CLI (Typer + Rich)
- Supabase migration discovery (`supabase/migrations/`, `schema.sql`, `seed.sql`)
- Schema reconstruction (tables, RLS state, and policies) from migrations,
  applied in order — including `CREATE`/`ALTER`/`DROP POLICY`
- **SUPA-RLS-001** — public table with RLS disabled
- **SUPA-RLS-002** — RLS enabled but no policies defined
- **SUPA-RLS-003** — unrestricted `using (true)` / `with check (true)` policy
  (severity scaled by operation and table sensitivity)
- **SUPA-RLS-004** — UPDATE policy with `USING` but no `WITH CHECK`
- **SUPA-RLS-005** — ownership column not protected by `auth.uid()` (graded
  confidence; higher when the column is a FK to `auth.users`)
- **SUPA-KEY-001** — privileged credential (service_role JWT, `sb_secret_`,
  DB password, Postgres connection string) exposed in source/env files;
  decodes JWT `role` claims so the anon/publishable key is never flagged
- **SUPA-STORAGE-001** — `storage.objects` policy that checks the bucket but
  not file ownership (`storage.foldername(name)` / `auth.uid()`)
- **SUPA-FUNC-001** — `SECURITY DEFINER` function surfaced for manual review,
  with risk signals (no `search_path`, dynamic SQL, data modification, no
  visible auth check) raising severity
- Scans JS/TS/JSX/TSX and `.env` files (skips `node_modules`, build dirs)
- Text and JSON output, `--fail-on` threshold, exit codes (0 / 1 / 2)
- **RAG explanations (`--explain`)** — retrieves relevant Supabase docs from a
  bundled corpus of curated documentation (offline BM25 with a rule-id boost)
  and attaches citations to each finding; optionally generates a
  beginner-friendly explanation via Claude when `ANTHROPIC_API_KEY` is set. The
  RAG layer only explains findings — it never decides whether a vulnerability
  exists — and always falls back to the predefined explanation.
- **Retrieval evaluation harness (`rlsguard rag-eval`)** — a labeled query set
  with standard IR metrics (hit rate, recall@k, precision@k, MRR), so retrieval
  quality is measured rather than assumed. Current corpus scores hit rate 1.00,
  MRR 1.00, recall@2 0.94, precision@2 0.81 over 18 queries, and a test guards
  against regressions.

## RAG explanations

```powershell
# Offline: attaches doc citations to each finding
rlsguard scan ./my-project --explain

# With AI synthesis (requires the optional extra + a key)
pip install -e .[rag]
$env:ANTHROPIC_API_KEY = "sk-ant-..."
rlsguard scan ./my-project --explain
```

### Measuring retrieval quality

The retriever is evaluated against a labeled query set so corpus or ranking
changes can be proven not to regress:

```powershell
rlsguard rag-eval            # summary metrics table
rlsguard rag-eval --verbose  # per-query retrieved docs
rlsguard rag-eval --json     # machine-readable metrics
```

## Install (development)

```powershell
py -m venv .venv
.venv\Scripts\pip install -e .[dev]
```

## Usage

```powershell
rlsguard scan ./my-project
rlsguard scan . --format json
rlsguard scan . --format sarif --output rlsguard.sarif
rlsguard scan . --fail-on high
```

Exit codes: `0` no findings at/above the threshold, `1` findings at/above the
threshold, `2` scanner error or invalid project.

## GitHub Actions

RLSGuard ships a reusable composite action (`action.yml`). It scans the repo,
uploads results to the GitHub **Security** tab as SARIF (inline PR annotations),
and fails the build on findings at/above the threshold.

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  rlsguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Sezman/RLSGuard@v1
        with:
          path: "."
          fail-on: "high"
```

See `.github/workflows/example-scan.yml` for a complete, copyable workflow.

## Tests

```powershell
.venv\Scripts\pytest -q
```
