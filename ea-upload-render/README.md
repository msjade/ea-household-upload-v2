EA Household Count Upload Platform (Render-ready)

What it does
- Accepts CSV uploads with strict template: NAT_EA_SN,HOUSEHOLD_COUNT
- Rejects duplicates inside the same CSV (same NAT_EA_SN repeated)
- Idempotent uploads: re-uploading the exact same file (internet retry) does not re-apply updates
- Detects cross-client conflicts (same EA updated by a different IP+User-Agent fingerprint within 60 days)
  and skips those conflicting rows
- No authentication (as requested)

Endpoints
- GET /            -> simple upload page
- POST /upload/hhcount  -> upload CSV and apply updates
- GET /healthz     -> health check

Database requirements
- You must have a table named ea_frame with a primary/unique key column NAT_EA_SN (text).
- The target column to update is HOUSEHOLD_COUNT (integer).

Notes about column casing
- This app auto-detects whether your ea_frame columns are stored as NAT_EA_SN/HOUSEHOLD_COUNT (quoted, uppercase)
  or as nat_ea_sn/household_count (unquoted, lowercase) and will work with either.

Run locally (Docker)
1) Build and run:
   docker build -t ea-upload ./app
   docker run -e DATABASE_URL='postgresql://user:pass@host:5432/db' -p 8000:8000 ea-upload

Deploy on Render.com (recommended)
1) Create a Render "PostgreSQL" instance.
2) Create a Render "Web Service" from this repo/folder and choose Docker.
3) Set environment variables:
   - DATABASE_URL: use the Render Postgres internal connection string
   - CONFLICT_WINDOW_DAYS: 60
   - TRUST_X_FORWARDED_FOR: true
4) Deploy.

CSV template
NAT_EA_SN,HOUSEHOLD_COUNT
12345,18
67890,7
