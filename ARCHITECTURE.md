ARCHITECTURE — QuickFixData (reconstructed)

Note: This architecture file was reconstructed from the current repository state (worker.js, wrangler.toml, vendored packages). It is a candidate for the frozen architecture required by QEOS. It MUST be reviewed and explicitly approved by the project owner before being treated as immutable.

1) Runtime & Deployment
- Platform: Cloudflare Workers (wrangler.toml present, main=worker.js)
- Deployment configuration: wrangler.toml, custom domain route api.quickfixdata.in, compatibility_date 2026-07-14
- Observability: enabled in wrangler.toml
- Cron triggers: two cron schedules defined in wrangler.toml (daily and weekly)

2) HTTP API / Surface
- Single Worker entry-point: worker.js implements HTTP API and action handlers
- CORS: configurable via ALLOWED_ORIGIN env var; defaults to "*" if unset
- Admin panel: embedded admin.html served from repo; admin actions protected via ADMIN_KEY secret

3) Storage & State
- Short-lived sessions: Cloudflare KV binding "SESSIONS" (wrangler.toml kv_namespaces)
- No other database files (no explicit D1/SQL usage detected in repository)
- Large artifacts (CSV) are processed in-memory and constrained (MAX_CSV_BYTES 8MB, MAX_CSV_ROWS 60k)

4) Payments Model
- UPI QR + manual confirmation workflow (no payment gateway): worker computes exact amount and reference; client scans QR and reports UTR; an admin manually confirms by checking bank/UPI statement.
- Reason: avoid gateway KYC/fees; simplified manual reconciliation.
- Secrets: UPI_ID and UPI_PAYEE_NAME provided via wrangler secrets (wrangler secret put)

5) Email intake & outgoing email
- Email intake: Cloudflare Email Routing -> forward to Worker (docs in worker.js comments)
- Outgoing email: optional integration with Resend (RESEND_API_KEY) — optional secret; fallback is send-via-Gmail UI action

6) AI integrations & privacy
- Optional Anthropic API integration (ANTHROPIC_API_KEY) used for "ask-your-data" and photo-to-data features (worker.js references)
- Privacy: worker.js documents explicit privacy notes and usage constraints

7) Third-party libraries / vendor
- postal-mime library vendored into repository under vendor/ and package/ (used for MIME parsing and email handling)

8) Security
- Admin actions rate-limited per IP (config constants in worker.js)
- Admin authentication uses constant-time comparison (safeEqual) to avoid timing attacks
- Secrets are expected to be provided via wrangler secrets, not checked into repo

9) Observability & Ops
- wrangler.toml observability enabled
- Cron triggers configured for scheduled tasks (daily and weekly)

10) Limitations & Known Gaps (from repository)
- No formal ADRs, ARCHITECTURE.md, ROADMAP, or milestone files found in repository (this file was reconstructed)
- No CI/workflow files (.github/workflows) detected in top-level repo (search limited; recommend adding CI for tests and linting)
- No top-level tests or test harness for the Worker application detected

11) Next: Freeze process
- This reconstructed architecture must be reviewed and approved by the project owner to become the frozen architecture. Once approved, further development will follow QEOS rules (no architecture redesign without explicit approval).

-- End of reconstructed architecture
