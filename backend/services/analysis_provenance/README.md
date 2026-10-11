# MailTrace-AI Analysis Provenance Ledger V1.1

Standalone drop-in package for:

`backend/services/analysis_provenance/`

## V1.1 additions

- Explicit finding-to-artifact lineage with backward-compatible legacy finding references.
- Finding lineage reciprocity/integrity validation.
- Replay comparison is observational and does not mutate execution state.
- Replay output comparison includes artifact type, SHA-256 fingerprint, parents, and finding lineage.
- Durable journal recovery for torn final lines and uncommitted journal tails.
- State/journal divergence is surfaced by `verify_chain()` instead of being silently accepted.
- Windows process-safe re-entrant persistence lock (`msvcrt`) with POSIX fallback for testability.
- Explicit per-record hash schema version (`1`).
- Backward-compatible state loading with `finding_bindings` migration.

## Drop-in install

Replace your existing:

`backend/services/analysis_provenance/`

with this folder.

Before replacement, make a normal backup of the current folder.

## Tests

Run from the backend directory:

```powershell
python -m services.analysis_provenance.tests.test_soc
python -m services.analysis_provenance.tests.test_high_assurance
```

Expected:

- baseline: `TOTAL_FAILS=0`
- V1.1: `V11_FAILS=0`

No new third-party dependency is required.

## Important compatibility behavior

Legacy callers may continue to finalize with `finding_ids` even when no finding artifact exists.
Such a reference is represented as `UNBOUND_LEGACY` and is never treated as artifact-backed provenance.

When a finding artifact explicitly carries a `finding_id`, or `finding_ids` are supplied to `register_artifact()`, the module records the reciprocal binding.

## Scope

This package is an analysis provenance/reproducibility ledger. It does not replace:

- evidence custody
- external integrity anchoring
- threat intelligence
- scoring
- email forensics
- case management

It records derivation and reproducibility relationships between those systems.
