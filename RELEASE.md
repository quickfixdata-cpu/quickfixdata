# Release Notes — EOS v1.0 RC1 (Candidate)

Release: RC1 (candidate for verification and review)

Contents
- All EOS v1.0 specification artifacts (Parts 1–12) are present under docs/.
- Canonical JSON Schemas: docs/schemas/
- Registries: docs/registries/
- Master indexes and manifests: docs/master_contract_index.json, docs/master_lifecycle_manifest.json, docs/master_decision_graph.json
- Evidence templates and placeholders: docs/evidence/, docs/_provenance/, docs/_recon/, docs/_reports/

What this release is for
- Staging verification, deterministic replay runs, and governance review.

Not production
- This RC1 is NOT the authoritative production release. Authoritative freeze requires human Approval Evidence and determinism_proof (see docs/GOVERNANCE.md).

How to validate
- Run schema validation against docs/schemas/.
- Run cross-reference checks using docs/cross_reference_map.json.
- Execute deterministic verification harness to produce determinism_proof.

Contact
- See docs/GOVERNANCE.md for signers and approval process.
