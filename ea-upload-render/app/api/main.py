import csv
import hashlib
import io
import os
import uuid
from typing import Dict, List, Tuple, Optional

from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# -----------------
# Config
# -----------------
RAW_DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not RAW_DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# Render often provides: postgresql://... ; SQLAlchemy psycopg dialect expects: postgresql+psycopg://...
if RAW_DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
elif RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL

CONFLICT_WINDOW_DAYS = int(os.environ.get("CONFLICT_WINDOW_DAYS", "60"))
TRUST_X_FORWARDED_FOR = os.environ.get("TRUST_X_FORWARDED_FOR", "true").lower() == "true"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="EA Household Count Uploader", version="1.0")
templates = Jinja2Templates(directory="templates")

# CSV template required columns
REQUIRED_HEADERS = ["NAT_EA_SN", "HOUSEHOLD_COUNT"]

# Resolved identifier names for ea_frame (supports either uppercase-quoted or normal lowercase)
EA_COLS: Dict[str, str] = {}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_source_ip(request: Request) -> str:
    if TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


def compute_fingerprint(source_ip: str, user_agent: str) -> str:
    raw = f"{source_ip}|{user_agent}".encode("utf-8", errors="ignore")
    return sha256_hex(raw)


def qident(name: str) -> str:
    """Safely quote an identifier (very conservative)."""
    return '"' + name.replace('"', '""') + '"'


def resolve_ea_frame_identifiers() -> Dict[str, str]:
    """Detect whether ea_frame uses uppercase quoted columns or normal lowercase."""
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'ea_frame'
                """
            )
        ).fetchall()

    existing = {r[0] for r in rows}

    # Prefer exact uppercase columns if present
    if "NAT_EA_SN" in existing and "HOUSEHOLD_COUNT" in existing:
        nat = qident("NAT_EA_SN")
        hh = qident("HOUSEHOLD_COUNT")
        upd_at = qident("HOUSEHOLD_COUNT_UPDATED_AT")
        upd_fp = qident("HOUSEHOLD_COUNT_SOURCE_FINGERPRINT")
        upd_id = qident("HOUSEHOLD_COUNT_LAST_UPLOAD_ID")
    else:
        # Fall back to lowercase (common Postgres behavior when created without quotes)
        nat = "nat_ea_sn"
        hh = "household_count"
        upd_at = "household_count_updated_at"
        upd_fp = "household_count_source_fingerprint"
        upd_id = "household_count_last_upload_id"

    return {
        "NAT": nat,
        "HH": hh,
        "UPD_AT": upd_at,
        "UPD_FP": upd_fp,
        "UPD_ID": upd_id,
        "HAS_UPPER": "NAT_EA_SN" in existing and "HOUSEHOLD_COUNT" in existing,
    }


def ensure_schema():
    """Create upload tracking + staging, and add tracking columns on ea_frame."""
    ddl = """
    CREATE TABLE IF NOT EXISTS upload_log (
      upload_id uuid PRIMARY KEY,
      received_at timestamptz NOT NULL DEFAULT now(),
      file_name text,
      file_sha256 text NOT NULL,
      source_ip text,
      user_agent text,
      source_fingerprint text NOT NULL,
      status text NOT NULL,
      total_rows int DEFAULT 0,
      valid_rows int DEFAULT 0,
      updated_rows int DEFAULT 0,
      skipped_conflicts int DEFAULT 0,
      invalid_rows int DEFAULT 0,
      error_summary text
    );

    CREATE UNIQUE INDEX IF NOT EXISTS ux_upload_filehash
    ON upload_log(file_sha256);

    CREATE TABLE IF NOT EXISTS staging_hh_update (
      upload_id uuid NOT NULL REFERENCES upload_log(upload_id) ON DELETE CASCADE,
      nat_ea_sn text NOT NULL,
      hh_count integer NOT NULL,
      PRIMARY KEY (upload_id, nat_ea_sn)
    );
    """

    with engine.begin() as conn:
        conn.execute(text(ddl))

    # add tracking columns based on resolved identifier casing
    cols = resolve_ea_frame_identifiers()
    alter_sql = f"""
    ALTER TABLE ea_frame
      ADD COLUMN IF NOT EXISTS {cols['UPD_AT']} timestamptz,
      ADD COLUMN IF NOT EXISTS {cols['UPD_FP']} text,
      ADD COLUMN IF NOT EXISTS {cols['UPD_ID']} uuid;
    """
    with engine.begin() as conn:
        conn.execute(text(alter_sql))

    # store globally
    EA_COLS.clear()
    EA_COLS.update(cols)


@app.on_event("startup")
def startup():
    ensure_schema()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def parse_and_check_duplicates(file_bytes: bytes) -> Tuple[List[Dict[str, str]], List[str]]:
    try:
        text_data = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded")

    f = io.StringIO(text_data)
    reader = csv.DictReader(f)

    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV is empty or missing header row")

    header_set = {h.strip() for h in reader.fieldnames if h}
    for h in REQUIRED_HEADERS:
        if h not in header_set:
            raise HTTPException(status_code=400, detail=f"Missing required column: {h}")

    rows: List[Dict[str, str]] = []
    seen = set()
    dups = set()

    for r in reader:
        nat = (r.get("NAT_EA_SN") or "").strip()
        hh = (r.get("HOUSEHOLD_COUNT") or "").strip()

        if nat:
            if nat in seen:
                dups.add(nat)
            else:
                seen.add(nat)

        rows.append({"NAT_EA_SN": nat, "HOUSEHOLD_COUNT": hh})

    return rows, sorted(list(dups))


def validate_rows(rows: List[Dict[str, str]]) -> Tuple[List[Tuple[str, int]], List[Dict[str, str]]]:
    valids: List[Tuple[str, int]] = []
    invalids: List[Dict[str, str]] = []

    for idx, r in enumerate(rows, start=2):
        nat = (r.get("NAT_EA_SN") or "").strip()
        hh_raw = (r.get("HOUSEHOLD_COUNT") or "").strip()

        if not nat:
            invalids.append({
                "line": str(idx),
                "NAT_EA_SN": nat,
                "HOUSEHOLD_COUNT": hh_raw,
                "error": "NAT_EA_SN is empty",
            })
            continue

        try:
            hh = int(hh_raw)
            if hh < 0:
                raise ValueError("negative")
        except Exception:
            invalids.append({
                "line": str(idx),
                "NAT_EA_SN": nat,
                "HOUSEHOLD_COUNT": hh_raw,
                "error": "HOUSEHOLD_COUNT must be integer >= 0",
            })
            continue

        valids.append((nat, hh))

    return valids, invalids


def nat_keys_exist(nats: List[str]) -> Tuple[List[str], List[str]]:
    if not nats:
        return [], []

    nat_col = EA_COLS["NAT"]

    with engine.begin() as conn:
        res = conn.execute(
            text(f"SELECT {nat_col} FROM ea_frame WHERE {nat_col} = ANY(:nats)"),
            {"nats": nats},
        ).fetchall()

    existing = {row[0] for row in res}
    missing = [n for n in nats if n not in existing]
    return list(existing), missing


@app.get("/template")
def download_template():
    return JSONResponse({"template_csv": "NAT_EA_SN,HOUSEHOLD_COUNT\n"})


@app.post("/upload/hhcount")
async def upload_hhcount(request: Request, file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    file_hash = sha256_hex(file_bytes)
    source_ip = get_source_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    fingerprint = compute_fingerprint(source_ip, user_agent)

    upload_id = uuid.uuid4()

    # Idempotency: same file hash should not be processed twice (internet retry/double click)
    with engine.begin() as conn:
        try:
            conn.execute(
                text(
                    """
                    INSERT INTO upload_log (upload_id, file_name, file_sha256, source_ip, user_agent, source_fingerprint, status)
                    VALUES (:upload_id, :file_name, :file_sha256, :source_ip, :user_agent, :fp, 'received')
                    """
                ),
                {
                    "upload_id": str(upload_id),
                    "file_name": file.filename,
                    "file_sha256": file_hash,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "fp": fingerprint,
                },
            )
        except IntegrityError:
            prev = conn.execute(
                text(
                    """
                    SELECT upload_id, received_at, status, total_rows, valid_rows, updated_rows,
                           skipped_conflicts, invalid_rows, error_summary
                    FROM upload_log
                    WHERE file_sha256 = :h
                    ORDER BY received_at DESC
                    LIMIT 1
                    """
                ),
                {"h": file_hash},
            ).mappings().first()

            return JSONResponse(
                {
                    "file_already_processed": True,
                    "conflict_window_days": CONFLICT_WINDOW_DAYS,
                    "previous_upload": dict(prev) if prev else None,
                }
            )

    # Parse + reject duplicates-in-file
    rows, dup_keys = parse_and_check_duplicates(file_bytes)
    if dup_keys:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE upload_log
                    SET status='rejected',
                        total_rows=:t,
                        invalid_rows=:inv,
                        error_summary=:err
                    WHERE upload_id=:upload_id
                    """
                ),
                {
                    "upload_id": str(upload_id),
                    "t": len(rows),
                    "inv": len(rows),
                    "err": f"Duplicate NAT_EA_SN found in file: {len(dup_keys)} duplicates",
                },
            )

        return JSONResponse(
            status_code=400,
            content={
                "file_already_processed": False,
                "status": "rejected",
                "reason": "duplicate_nat_ea_sn_in_file",
                "duplicate_nat_ea_sn": dup_keys[:2000],
                "conflict_window_days": CONFLICT_WINDOW_DAYS,
            },
        )

    # Validate values
    valid_pairs, invalid_rows = validate_rows(rows)

    # Ensure NAT_EA_SN exists in ea_frame (we do NOT create new EAs)
    nats = [nat for nat, _ in valid_pairs]
    _, missing = nat_keys_exist(nats)
    missing_set = set(missing)

    final_valids = [(nat, hh) for nat, hh in valid_pairs if nat not in missing_set]

    invalid_rows2 = list(invalid_rows)
    for nat in missing:
        invalid_rows2.append({
            "line": "",
            "NAT_EA_SN": nat,
            "HOUSEHOLD_COUNT": "",
            "error": "NAT_EA_SN not found in ea_frame",
        })

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE upload_log
                SET status='validated',
                    total_rows=:t,
                    valid_rows=:v,
                    invalid_rows=:inv
                WHERE upload_id=:upload_id
                """
            ),
            {"upload_id": str(upload_id), "t": len(rows), "v": len(final_valids), "inv": len(invalid_rows2)},
        )

    if not final_valids:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE upload_log
                    SET status='rejected',
                        error_summary='No valid rows to apply'
                    WHERE upload_id=:upload_id
                    """
                ),
                {"upload_id": str(upload_id)},
            )

        return JSONResponse(
            status_code=400,
            content={
                "file_already_processed": False,
                "status": "rejected",
                "reason": "no_valid_rows",
                "invalid_rows_sample": invalid_rows2[:2000],
                "conflict_window_days": CONFLICT_WINDOW_DAYS,
            },
        )

    # Load into staging
    with engine.begin() as conn:
        values_sql = ", ".join([f"(:upload_id, :nat{i}, :hh{i})" for i in range(len(final_valids))])
        params: Dict[str, object] = {"upload_id": str(upload_id)}
        for i, (nat, hh) in enumerate(final_valids):
            params[f"nat{i}"] = nat
            params[f"hh{i}"] = hh

        conn.execute(text(f"INSERT INTO staging_hh_update (upload_id, nat_ea_sn, hh_count) VALUES {values_sql}"), params)

    nat_col = EA_COLS["NAT"]
    hh_col = EA_COLS["HH"]
    upd_at = EA_COLS["UPD_AT"]
    upd_fp = EA_COLS["UPD_FP"]
    upd_id = EA_COLS["UPD_ID"]

    # Cross-client conflict detection within CONFLICT_WINDOW_DAYS
    with engine.begin() as conn:
        conflict_rows = conn.execute(
            text(
                f"""
                SELECT s.nat_ea_sn,
                       s.hh_count,
                       e.{hh_col} AS existing_household_count,
                       e.{upd_at} AS household_count_updated_at,
                       e.{upd_fp} AS household_count_source_fingerprint
                FROM staging_hh_update s
                JOIN ea_frame e ON e.{nat_col} = s.nat_ea_sn
                WHERE s.upload_id = :upload_id
                  AND e.{upd_id} IS NOT NULL
                  AND e.{upd_fp} IS DISTINCT FROM :fp
                  AND e.{upd_at} >= now() - interval '{CONFLICT_WINDOW_DAYS} days'
                """
            ),
            {"upload_id": str(upload_id), "fp": fingerprint},
        ).mappings().all()

        conflicts = [dict(r) for r in conflict_rows]

    # Apply updates for non-conflict rows only
    with engine.begin() as conn:
        result = conn.execute(
            text(
                f"""
                UPDATE ea_frame e
                SET {hh_col} = s.hh_count,
                    {upd_at} = now(),
                    {upd_fp} = :fp,
                    {upd_id} = :upload_id
                FROM staging_hh_update s
                WHERE s.upload_id = :upload_id
                  AND e.{nat_col} = s.nat_ea_sn
                  AND NOT (
                    e.{upd_id} IS NOT NULL
                    AND e.{upd_fp} IS DISTINCT FROM :fp
                    AND e.{upd_at} >= now() - interval '{CONFLICT_WINDOW_DAYS} days'
                  );
                """
            ),
            {"upload_id": str(upload_id), "fp": fingerprint},
        )
        updated_rows = int(result.rowcount or 0)

        conn.execute(
            text(
                """
                UPDATE upload_log
                SET status='applied',
                    updated_rows=:u,
                    skipped_conflicts=:s,
                    error_summary=:err
                WHERE upload_id=:upload_id
                """
            ),
            {
                "upload_id": str(upload_id),
                "u": updated_rows,
                "s": len(conflicts),
                "err": None if updated_rows > 0 else "No rows updated (all conflicted or none matched)",
            },
        )

    return JSONResponse(
        {
            "file_already_processed": False,
            "status": "applied",
            "upload_id": str(upload_id),
            "conflict_window_days": CONFLICT_WINDOW_DAYS,
            "summary": {
                "total_rows_in_file": len(rows),
                "valid_rows_loaded": len(final_valids),
                "invalid_rows": len(invalid_rows2),
                "updated_rows": updated_rows,
                "skipped_conflicts": len(conflicts),
            },
            "invalid_rows_sample": invalid_rows2[:50],
            "conflicts_sample": conflicts[:50],
            "fingerprint_used": fingerprint,
        }
    )
