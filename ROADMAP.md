ROADMAP — QuickFixData (candidate)

Note: This roadmap is a candidate reconstructed from the repository and the developer's intent embedded in code comments. It must be reviewed and aligned with product priorities before implementation.

Milestone 0 — Freeze Architecture (priority: immediate)
- Review ADR-0001 (reconstructed architecture) and ARCHITECTURE.md
- Owner approval to treat these as frozen architecture

Milestone 1 — Security & Secrets Hardening
- Verify wrangler secrets for production (ADMIN_KEY, UPI_ID, UPI_PAYEE_NAME, RESEND_API_KEY, ANTHROPIC_API_KEY, OWNER_EMAIL)
- Add secret rotation and vault documentation
- Security review: rate limits, admin key protections, XSS fixes already present in code; run security audit

Milestone 2 — CI, Tests, and QA
- Add GitHub Actions for lint, type-check, and Node unit tests (postal-mime package has tests; ensure Worker code has test harness)
- Create unit tests for critical flows: CSV parsing, payment claim lifecycle, admin actions, email intake parsing

Milestone 3 — Monitoring & Backups
- Configure observability retention, alerts, and log sinks
- Add backup plan (if any persistent DB used later)

Milestone 4 — Release & Runbook
- Document deployment steps (wrangler publish, secrets setup)
- Create runbook for manual payment confirmations, refund/reject procedures, and incident response

Milestone 5 — Optional Enhancements
- Automatic payment confirmation via forwarded bank emails (v10 feature) — gated behind strict OWNER_EMAIL authenticated forwarding
- Photo-to-data via Anthropic vision (requires API keys and privacy review)
- Add optional payment gateway integration (Razorpay/Cashfree) if automatic reconciliation needed

-- End Roadmap
