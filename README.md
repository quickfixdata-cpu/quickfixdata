# QuickFixData — EOS v1.0 Candidate Repository

This repository contains the QuickFixData Engineering Operating System (EOS) v1.0 candidate artifacts.

Purpose
- Provide the EOS v1.0 specification artifacts, schemas, registries, lifecycle, decision graph, contract index, and evidence templates for review and staging verification.

Contents
- docs/: EOS artifacts (schemas, registries, manifests, templates)
- ARCHITECTURE.md, ADR-0001-RECONSTRUCTED-ARCHITECTURE.md, ROADMAP.md
- worker.js, wrangler.toml: application runtime artifacts (do not modify for EOS verification)

Usage
- This is a release candidate (RC1). Do not treat artifacts as authoritative until human Approval Evidence is recorded (see docs/GOVERNANCE.md).
- For verification, deploy to a staging environment and run deterministic verification harnesses.

Status
- EOS v1.0 candidate artifacts are seeded in docs/ and require human Approval Evidence and a representative determinism_proof to be promoted to authoritative.

Contact
- See docs/GOVERNANCE.md for owner roles and escalation paths.
