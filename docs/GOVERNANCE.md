# EOS Governance Document

## Purpose

This document defines the canonical governance controls, owner roles, and Approval Evidence process for the QuickFixData EOS v1.0 Specification. It is authoritative for repository-level governance artifacts and freeze readiness.

## Governance Scope

This governance document covers:
- Owner role definitions and responsibilities.
- Approval Evidence requirements and artifact conventions.
- Signing key references and verification rules.
- Contact and escalation guidance for the EOS v1.0 freeze.
- Repository artifact retention and audit requirements.

## Owner Roles

The following owner roles are defined for EOS v1.0. Each role is responsible for the corresponding engine domains and governance execution.

- Chief EOS Architect
  - Owner of the Master Control Plane and the EOS v1.0 specification.
  - Responsible for final architectural sign-off, deterministic guarantees, and control plane consistency.

- Standards Committee Chair
  - Owner of specification quality, consistency, and compliance across Parts 1–12.
  - Responsible for leading the EOS Specification Editorial Board and final freeze checklist validation.

- Governance Board Representative
  - Owner of Approval Evidence policy, repository control decisions, and governance enforcement.
  - Responsible for validating and authorizing freeze-related governance artifacts.

- Chief Systems Architect
  - Owner of system-level architectural coherence across runtime, deployment, observability, and operations.
  - Responsible for validating architecture-to-implementation alignment and operational readiness.

- Execution Planner Owner
  - Owner of the Execution Planner Engine and execution_manifest definitions.

- Dependency Resolution Owner
  - Owner of dependency resolution and capability dependency validation.

- Scheduler Owner
  - Owner of deterministic scheduling and resource allocation decisions.

- Context Manager
  - Owner of context_snapshot definitions and execution context management.

- State Manager
  - Owner of state transitions, checkpoints, and recovery state.

- Decision Engine Owner
  - Owner of deterministic decision scoring and decision_record production.

- Failure Recovery Owner
  - Owner of failure recovery planning and recovery workflow definitions.

- Evidence Aggregation Owner
  - Owner of evidence_graph assembly and evidence catalog definitions.

- Global Validation Owner
  - Owner of global_validation_report criteria and validation workflows.

- Runtime Optimization Owner
  - Owner of optimization planning and cache reuse strategy.

- Human Interaction Owner
  - Owner of approval request lifecycle and signed_approval artifacts.

- Audit Owner
  - Owner of audit_bundle production and audit retention policies.

- Policy Enforcement Owner
  - Owner of policy_registry and enforcement decision provenance.

- Multi-Agent Coordinator
  - Owner of agent assignment, synchronization, and coordination plans.

- Contracts Owner
  - Owner of runtime_contract validation and schema conformance.

- Metrics Owner
  - Owner of runtime metrics collection and metric reporting.

- Determinism Owner
  - Owner of determinism_proof generation and replay verification.

- API Owner
  - Owner of runtime APIs and external interface contracts.

- Lifecycle Owner
  - Owner of the EOS lifecycle_manifest and lifecycle transition rules.

- Chief Governance Auditor
  - Owner of audit preparedness and governance evidence mapping.

## Approval Evidence Requirements

Approval Evidence is mandatory for any authoritative EOS v1.0 actions, including specification freeze, registry seeding, and release readiness.

### Definition

Approval Evidence is a signed artifact that contains:
- approval_id: canonical identifier.
- signer_role: owner role identity.
- signed_timestamp: UTC timestamp.
- approval_scope: the artifact, freeze checklist, or decision being authorized.
- evidence_references: list of artifact ids and checksum references.
- signature_checksum: content checksum of the signed artifact.
- provenance: { run_seed, recon_id, commit_sha, config_version }.

### Acceptable Approval Evidence forms

1. Signed PR merge metadata
   - Requires a merged pull request with the label `arch:approved`.
   - Requires signed commits or equivalent repository provenance.
   - Requires an associated signed_approval artifact recorded in `docs/_provenance/`.

2. Governance Tracker approval
   - Requires a Governance Board Representative or equivalent authorized role to record an approval in the governance tracker.
   - Requires the corresponding signed_approval artifact stored in `docs/_provenance/`.

### Required signers for EOS v1.0 freeze

The following roles must produce Approval Evidence for EOS v1.0 freeze:
- Chief EOS Architect
- Standards Committee Chair
- Governance Board Representative
- Chief Systems Architect (recommended)

Signers must be documented by role in the signed_approval artifact.

## Signing Key References

Approval Evidence artifacts must reference one or more signing keys. The signing key references are expressed as:
- signing_key_id: canonical identifier for the signing key.
- public_key_fingerprint: cryptographic fingerprint for verification.
- key_owner_role: owner role that controls the key.
- key_use: approved usage for the key (e.g., approval evidence signing, audit signing).

### Example signing key manifest entry

```yaml
signing_key_id: eos-governance-key-v1
public_key_fingerprint: "SHA256:..."
key_owner_role: Governance Board Representative
key_use: signed_approval artifact signing
```

## Repository Governance Standards

The EOS v1.0 governance strategy enforces the following repository conventions:
- No authoritative artifact is considered frozen without Approval Evidence.
- Candidate artifacts may be created under `docs/` and `docs/drafts/`, but only those accompanied by Approval Evidence become authoritative.
- All governance artifacts must include provenance metadata.
- Registry and schema artifacts must be versioned and validated prior to promotion.
- Branch protection and enforcement webhook configuration plans must be documented and reviewed.

## Contact and Escalation

When governance uncertainty or blocker remediation is required, use the following roles:
- Primary escalation: Governance Board Representative
- Secondary escalation: Chief EOS Architect
- Tertiary escalation: Standards Committee Chair

Contact details SHALL be maintained separately from this freeze document in the organization's approved contact directory.

## Audit and Retention

All governance artifacts related to EOS v1.0 must be retained in the repository or approved evidence store.
- `docs/_provenance/`: signed_approval artifacts and provenance proofs.
- `docs/_recon/`: reconstruction and repository state reports.
- `docs/_reports/`: validation, audit, and decision reports.

Retention policy:
- Artifacts retained for EOS v1.0 must be preserved for the life of the project plus one retention cycle as defined by organizational policy.

## Freeze Readiness

EOS v1.0 can be considered freeze-ready only when:
- All required schema and registry artifacts are committed.
- Required owner roles are defined and sign-off roles are available.
- Approval Evidence for the freeze is recorded and verifiable.
- The freeze checklist is completed and evidenced.

## Change Control

Any changes to this document after EOS v1.0 freeze must be governed by the EOS change control process and require re-approval from the Standards Committee Chair and Governance Board Representative.
