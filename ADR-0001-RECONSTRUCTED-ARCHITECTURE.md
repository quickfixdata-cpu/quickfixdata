ADR-0001: Reconstructed Architecture — QuickFixData

Status: Proposed (reconstructed from repository implementation)
Date: 2026-08-05

Context
-------
The repository lacked an explicit frozen architecture or ADRs. The codebase (worker.js, wrangler.toml, vendored packages) demonstrates the implemented architecture decisions. To proceed under QEOS (which requires a frozen architecture), the project owner must approve a reconstruction of the architecture based on the repository. This ADR records the reconstruction and the primary architectural decisions observed.

Decision
--------
1) Platform: Use Cloudflare Workers for HTTP API and processing (worker.js, wrangler.toml).
2) State: Use Cloudflare KV (binding "SESSIONS") for short-lived session state. No server-side relational DB detected.
3) Payments: Use UPI QR + manual UTR-based confirmation. No payment gateway is integrated.
4) Email: Accept inbound email via Cloudflare Email Routing -> Worker. Use vendor postal-mime for parsing MIME emails.
5) AI Integration: Optional Anthropic API for data-summary features (requires ANTHROPIC_API_KEY secret).
6) Secrets: All sensitive keys are provided via wrangler secret put; no secrets should be committed.

Consequences
-----------
- Operational: Manual payment confirmation requires admin involvement; future gateway integration is possible by replacing confirmPaymentClaim flow.
- Security: Secrets must be managed via wrangler secrets. Admin_key must be rotated and stored securely.
- Development: Tests, CI, and formal ADRs are missing and must be added.

Acceptance
---------
This ADR is a reconstruction. It requires explicit approval by the repository owner/maintainer to be treated as the frozen architecture. Approve by adding a commit that references ADR-0001 or by replying in the issue/PR tracking system.

-- End ADR-0001
