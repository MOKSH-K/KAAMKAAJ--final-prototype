from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Iterator
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("KAAMKAAJ_DATABASE", BASE_DIR / "kaamkaaj.db"))
SESSION_COOKIE = "kaamkaaj_session"
SESSION_DURATION = timedelta(days=7)
BOOKING_RESPONSE_WINDOW = timedelta(minutes=2)
PASSWORD_ITERATIONS = 310_000
SERVICES = {
    "sweeping",
    "mopping",
    "washing_vessels",
    "laundry",
    "dusting",
    "balcony_cleaning",
    "ironing_and_folding",
    "kitchen_prep",
}
PROPERTY_TYPES = {
    "1_bhk",
    "2_bhk",
    "3_bhk",
    "4_bhk",
    "penthouse",
    "villa",
    "studio",
    "other",
}
USER_ONLY_PAGES = {
    "moksh_homeservices.html",
    "packages.html",
    "booking_submission.html",
    "booking_waiting.html",
}
WORKER_ONLY_PAGES = {"workers_home.html"}


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                phone TEXT NOT NULL,
                address TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                service_area TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                role TEXT NOT NULL CHECK(role IN ('user', 'worker')),
                account_id INTEGER NOT NULL,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS service_requests (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                services TEXT NOT NULL,
                property_type TEXT,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'accepted')),
                worker_id INTEGER REFERENCES workers(id),
                cancelled_at TEXT,
                accepted_at TEXT,
                address TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS contact_submissions (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        request_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(service_requests)")
        }
        user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        worker_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workers)")}
        if "address" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN address TEXT NOT NULL DEFAULT ''")
        if "service_area" not in worker_columns:
            connection.execute(
                "ALTER TABLE workers ADD COLUMN service_area TEXT NOT NULL DEFAULT ''"
            )
        if "status" not in request_columns:
            connection.execute(
                "ALTER TABLE service_requests ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
            )
        if "worker_id" not in request_columns:
            connection.execute(
                "ALTER TABLE service_requests ADD COLUMN worker_id INTEGER REFERENCES workers(id)"
            )
        if "cancelled_at" not in request_columns:
            connection.execute(
                "ALTER TABLE service_requests ADD COLUMN cancelled_at TEXT"
            )
        if "accepted_at" not in request_columns:
            connection.execute(
                "ALTER TABLE service_requests ADD COLUMN accepted_at TEXT"
            )
        if "address" not in request_columns:
            connection.execute(
                "ALTER TABLE service_requests ADD COLUMN address TEXT NOT NULL DEFAULT ''"
            )
        connection.execute(
            """
            UPDATE service_requests
            SET address = COALESCE(
                (SELECT address FROM users WHERE users.id = service_requests.user_id),
                ''
            )
            WHERE address = ''
            """
        )
        connection.execute(
            """
            UPDATE service_requests
            SET accepted_at = created_at
            WHERE status = 'accepted' AND accepted_at IS NULL
            """
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserSignup(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone_no: str = Field(min_length=7, max_length=30)
    address: str = Field(min_length=1, max_length=500)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("address")
    @classmethod
    def address_must_not_be_blank(cls, value: str) -> str:
        address = value.strip()
        if not address:
            raise ValueError("A service address is required.")
        return address


class WorkerSignup(BaseModel):
    worker_name: str = Field(min_length=1, max_length=120)
    phone_number: str = Field(min_length=7, max_length=30)
    service_area: str = Field(min_length=1, max_length=250)
    worker_pass: str = Field(min_length=8, max_length=128)

    @field_validator("service_area")
    @classmethod
    def service_area_must_not_be_blank(cls, value: str) -> str:
        service_area = value.strip()
        if not service_area:
            raise ValueError("A worker service area is required.")
        return service_area


class WorkerServiceAreaUpdate(BaseModel):
    service_area: str = Field(min_length=1, max_length=250)

    @field_validator("service_area")
    @classmethod
    def service_area_must_not_be_blank(cls, value: str) -> str:
        service_area = value.strip()
        if not service_area:
            raise ValueError("A worker service area is required.")
        return service_area


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class WorkerLogin(BaseModel):
    phone_number: str = Field(min_length=7, max_length=30)
    worker_pass: str = Field(min_length=1, max_length=128)


class ContactSubmission(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phone_number: str = Field(min_length=7, max_length=30)
    description: str = Field(min_length=1, max_length=5000)


class ServiceRequest(BaseModel):
    services: list[str] = Field(min_length=1, max_length=8)
    property_type: str
    address: str = Field(min_length=1, max_length=500)

    @field_validator("services")
    @classmethod
    def services_must_be_supported(cls, services: list[str]) -> list[str]:
        if len(set(services)) != len(services):
            raise ValueError("Services must not contain duplicates.")
        unsupported = set(services) - SERVICES
        if unsupported:
            raise ValueError("One or more selected services are not supported.")
        return services

    @field_validator("property_type")
    @classmethod
    def property_type_must_be_supported(cls, value: str) -> str:
        if value not in PROPERTY_TYPES:
            raise ValueError("The selected property type is not supported.")
        return value

    @field_validator("address")
    @classmethod
    def address_must_not_be_blank(cls, value: str) -> str:
        address = value.strip()
        if not address:
            raise ValueError("A service address is required.")
        return address


class AccountSession(BaseModel):
    account_id: int
    role: str
    name: str
    csrf_token: str
    address: str | None = None
    service_area: str | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Kaamkaaj API", version="1.0.0", lifespan=lifespan)
cors_origins = [
    origin.strip()
    for origin in os.getenv("KAAMKAAJ_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
app.mount("/images", StaticFiles(directory=BASE_DIR.parent / "images"), name="images")


def set_session_cookie(response: Response, account_id: int, role: str) -> str:
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = utc_now()
    with get_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (timestamp(now),))
        connection.execute(
            """
            INSERT INTO sessions (token_hash, role, account_id, csrf_token, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                token_digest(session_token),
                role,
                account_id,
                csrf_token,
                timestamp(now + SESSION_DURATION),
                timestamp(now),
            ),
        )
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=int(SESSION_DURATION.total_seconds()),
        httponly=True,
        secure=os.getenv("KAAMKAAJ_COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        path="/",
    )
    return csrf_token


def get_current_account(request: Request) -> AccountSession:
    session_token = request.cookies.get(SESSION_COOKIE)
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please sign in.")

    expired = False
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT s.account_id, s.role, s.csrf_token, s.expires_at,
                   CASE s.role WHEN 'user' THEN u.name ELSE w.name END AS name,
                   u.address AS address, w.service_area AS service_area
            FROM sessions AS s
            LEFT JOIN users AS u ON s.role = 'user' AND u.id = s.account_id
            LEFT JOIN workers AS w ON s.role = 'worker' AND w.id = s.account_id
            WHERE s.token_hash = ?
            """,
            (token_digest(session_token),),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please sign in.")
        if datetime.fromisoformat(row["expires_at"]) <= utc_now():
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(session_token),)
            )
            expired = True
        elif row["name"] is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found.")
        else:
            account = AccountSession(
                account_id=row["account_id"],
                role=row["role"],
                name=row["name"],
                csrf_token=row["csrf_token"],
                address=row["address"],
                service_area=row["service_area"],
            )
    if expired:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired.")
    return account


CurrentAccount = Annotated[AccountSession, Depends(get_current_account)]


def require_csrf(request: Request, account: AccountSession) -> None:
    supplied_token = request.headers.get("X-CSRF-Token", "")
    if not supplied_token or not hmac.compare_digest(supplied_token, account.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token.")


def login_account(
    response: Response,
    role: str,
    account_id: int,
    name: str,
    message: str,
) -> dict[str, str]:
    set_session_cookie(response, account_id, role)
    return {"status": "success", "message": message, "name": name}


@app.get("/")
def root() -> FileResponse:
    return FileResponse(BASE_DIR / "home.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/signup")
def signup_user(data: UserSignup, response: Response) -> dict[str, str]:
    name = data.username.strip()
    phone = data.phone_no.strip()
    if not name or not phone:
        raise HTTPException(status_code=422, detail="Name and phone number are required.")
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (name, email, phone, address, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    data.email,
                    phone,
                    data.address,
                    hash_password(data.password),
                    timestamp(),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with that email already exists.") from exc
    return login_account(response, "user", cursor.lastrowid, name, "Account created successfully.")


@app.post("/worker-signup")
def signup_worker(data: WorkerSignup, response: Response) -> dict[str, str]:
    name = data.worker_name.strip()
    phone = data.phone_number.strip()
    if not name or not phone:
        raise HTTPException(status_code=422, detail="Name and phone number are required.")
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO workers (name, phone, service_area, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, phone, data.service_area, hash_password(data.worker_pass), timestamp()),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A worker account with that phone number already exists.") from exc
    return login_account(response, "worker", cursor.lastrowid, name, "Worker account created successfully.")


@app.post("/login")
def login_user(data: UserLogin, response: Response) -> dict[str, str]:
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, name, password_hash FROM users WHERE email = ? COLLATE NOCASE",
            (str(data.email),),
        ).fetchone()
    if user is None or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return login_account(response, "user", user["id"], user["name"], "Login successful.")


@app.post("/worker-login")
def login_worker(data: WorkerLogin, response: Response) -> dict[str, str]:
    with get_connection() as connection:
        worker = connection.execute(
            "SELECT id, name, password_hash FROM workers WHERE phone = ?",
            (data.phone_number.strip(),),
        ).fetchone()
    if worker is None or not verify_password(data.worker_pass, worker["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid phone number or password.")
    return login_account(response, "worker", worker["id"], worker["name"], "Login successful.")


@app.get("/auth/me")
def get_session(account: CurrentAccount) -> dict[str, Any]:
    return {
        "authenticated": True,
        "role": account.role,
        "name": account.name,
        "address": account.address,
        "service_area": account.service_area,
        "csrf_token": account.csrf_token,
    }


@app.post("/worker/service-area")
def update_worker_service_area(
    data: WorkerServiceAreaUpdate,
    request: Request,
    account: CurrentAccount,
) -> dict[str, str]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can update a service area.")
    require_csrf(request, account)
    with get_connection() as connection:
        connection.execute(
            "UPDATE workers SET service_area = ? WHERE id = ?",
            (data.service_area, account.account_id),
        )
    return {"status": "success", "service_area": data.service_area}


@app.post("/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        with get_connection() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(session_token),)
            )
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=os.getenv("KAAMKAAJ_COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
    )
    return {"status": "success", "message": "Logged out successfully."}


@app.post("/service-requests", status_code=status.HTTP_201_CREATED)
def create_service_request(
    data: ServiceRequest,
    request: Request,
    account: CurrentAccount,
) -> dict[str, Any]:
    if account.role != "user":
        raise HTTPException(status_code=403, detail="Only user accounts can create bookings.")
    require_csrf(request, account)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO service_requests (user_id, services, property_type, created_at, status, address)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (
                account.account_id,
                ",".join(data.services),
                data.property_type,
                timestamp(),
                data.address,
            ),
        )
        connection.execute(
            "UPDATE users SET address = ? WHERE id = ?",
            (data.address, account.account_id),
        )
    return {
        "status": "success",
        "id": cursor.lastrowid,
        "booking_status": "pending",
        "message": "Booking created successfully.",
    }


@app.get("/service-requests/{request_id}")
def get_service_request_status(request_id: int, account: CurrentAccount) -> dict[str, Any]:
    if account.role != "user":
        raise HTTPException(status_code=403, detail="Only user accounts can view bookings.")
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT sr.id, sr.services, sr.property_type, sr.status, sr.created_at,
                   sr.cancelled_at,
                   w.name AS worker_name, w.phone AS worker_phone,
                   w.service_area AS worker_service_area
            FROM service_requests AS sr
            LEFT JOIN workers AS w ON w.id = sr.worker_id
            WHERE sr.id = ? AND sr.user_id = ?
            """,
            (request_id, account.account_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Booking not found.")
    booking_status = "cancelled" if row["cancelled_at"] else row["status"]
    if (
        booking_status == "pending"
        and utc_now() >= datetime.fromisoformat(row["created_at"]) + BOOKING_RESPONSE_WINDOW
    ):
        booking_status = "unavailable"
    return {
        "id": row["id"],
        "services": row["services"].split(","),
        "property_type": row["property_type"],
        "status": booking_status,
        "created_at": row["created_at"],
        "worker_name": row["worker_name"] if booking_status == "accepted" else None,
        "worker_phone": row["worker_phone"] if booking_status == "accepted" else None,
        "worker_service_area": (
            row["worker_service_area"] if booking_status == "accepted" else None
        ),
    }


@app.post("/service-requests/{request_id}/cancel")
def cancel_service_request(
    request_id: int,
    request: Request,
    account: CurrentAccount,
) -> dict[str, Any]:
    if account.role != "user":
        raise HTTPException(status_code=403, detail="Only user accounts can cancel bookings.")
    require_csrf(request, account)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE service_requests
            SET cancelled_at = ?
            WHERE id = ? AND user_id = ? AND status = 'pending' AND cancelled_at IS NULL
            """,
            (timestamp(), request_id, account.account_id),
        )
        if cursor.rowcount == 0:
            row = connection.execute(
                """
                SELECT status, cancelled_at
                FROM service_requests
                WHERE id = ? AND user_id = ?
                """,
                (request_id, account.account_id),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Booking not found.")
            if row["cancelled_at"] is not None:
                return {"status": "success", "booking_status": "cancelled"}
            raise HTTPException(
                status_code=409,
                detail="This booking can no longer be cancelled because a worker has accepted it.",
            )
    return {
        "status": "success",
        "booking_status": "cancelled",
        "message": "Booking cancelled.",
    }


@app.get("/worker/service-requests")
def list_pending_service_requests(account: CurrentAccount) -> dict[str, Any]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can view incoming bookings.")
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT sr.id, sr.services, sr.property_type, sr.created_at,
                   u.name AS customer_name, u.email AS customer_email, u.phone AS customer_phone,
                   COALESCE(NULLIF(sr.address, ''), u.address) AS customer_address
            FROM service_requests AS sr
            JOIN users AS u ON u.id = sr.user_id
            WHERE sr.status = 'pending' AND sr.cancelled_at IS NULL AND sr.created_at >= ?
            ORDER BY sr.created_at ASC
            """,
            (timestamp(utc_now() - BOOKING_RESPONSE_WINDOW),),
        ).fetchall()
    return {
        "requests": [
            {
                "id": row["id"],
                "services": row["services"].split(","),
                "property_type": row["property_type"],
                "created_at": row["created_at"],
                "customer_name": row["customer_name"],
                "customer_email": row["customer_email"],
                "customer_phone": row["customer_phone"],
                "customer_address": row["customer_address"],
            }
            for row in rows
        ]
    }


@app.get("/worker/stats")
def get_worker_stats(
    account: CurrentAccount,
    local_date: date,
    timezone_offset_minutes: int = 0,
) -> dict[str, int]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can view worker statistics.")
    if not -840 <= timezone_offset_minutes <= 840:
        raise HTTPException(status_code=422, detail="Timezone offset must be between -840 and 840 minutes.")

    local_timezone = timezone(timedelta(minutes=-timezone_offset_minutes))
    start_of_day = datetime.combine(local_date, time.min, tzinfo=local_timezone)
    start_of_next_day = datetime.combine(
        local_date + timedelta(days=1),
        time.min,
        tzinfo=local_timezone,
    )
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS completed_jobs_today
            FROM service_requests
            WHERE worker_id = ? AND status = 'accepted'
                AND accepted_at >= ? AND accepted_at < ? AND cancelled_at IS NULL
            """,
            (
                account.account_id,
                timestamp(start_of_day.astimezone(timezone.utc)),
                timestamp(start_of_next_day.astimezone(timezone.utc)),
            ),
        ).fetchone()
    return {"completed_jobs_today": row["completed_jobs_today"]}


@app.get("/worker/activity")
def get_worker_activity(account: CurrentAccount) -> dict[str, Any]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can view worker activity.")
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT sr.id, sr.services, sr.accepted_at, u.name AS customer_name
            FROM service_requests AS sr
            JOIN users AS u ON u.id = sr.user_id
            WHERE sr.worker_id = ? AND sr.status = 'accepted' AND sr.accepted_at IS NOT NULL
                AND sr.cancelled_at IS NULL
            ORDER BY sr.accepted_at DESC, sr.id DESC
            """,
            (account.account_id,),
        ).fetchall()
    return {
        "activities": [
            {
                "id": row["id"],
                "services": row["services"].split(","),
                "accepted_at": row["accepted_at"],
                "customer_name": row["customer_name"],
            }
            for row in rows
        ]
    }


@app.post("/worker/service-requests/{request_id}/accept")
def accept_service_request(
    request_id: int,
    request: Request,
    account: CurrentAccount,
) -> dict[str, Any]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can accept bookings.")
    require_csrf(request, account)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE service_requests
            SET status = 'accepted', worker_id = ?, accepted_at = ?
            WHERE id = ? AND status = 'pending' AND cancelled_at IS NULL AND created_at >= ?
            """,
            (
                account.account_id,
                timestamp(utc_now()),
                request_id,
                timestamp(utc_now() - BOOKING_RESPONSE_WINDOW),
            ),
        )
        if cursor.rowcount == 0:
            exists = connection.execute(
                "SELECT status, cancelled_at, created_at FROM service_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Booking not found.")
            if exists["cancelled_at"] is not None:
                raise HTTPException(status_code=409, detail="This booking has been cancelled.")
            if (
                exists["status"] == "pending"
                and utc_now()
                >= datetime.fromisoformat(exists["created_at"]) + BOOKING_RESPONSE_WINDOW
            ):
                raise HTTPException(
                    status_code=409,
                    detail="This booking expired because no worker accepted it in time.",
                )
            raise HTTPException(status_code=409, detail="This booking has already been accepted.")
    return {
        "status": "success",
        "booking_status": "accepted",
        "worker_name": account.name,
        "message": "Booking accepted.",
    }


@app.post("/worker/service-requests/{request_id}/cancel")
def cancel_accepted_service_request(
    request_id: int,
    request: Request,
    account: CurrentAccount,
) -> dict[str, str]:
    if account.role != "worker":
        raise HTTPException(status_code=403, detail="Only worker accounts can cancel accepted bookings.")
    require_csrf(request, account)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE service_requests
            SET cancelled_at = ?
            WHERE id = ? AND worker_id = ? AND status = 'accepted' AND cancelled_at IS NULL
            """,
            (timestamp(), request_id, account.account_id),
        )
        if cursor.rowcount == 0:
            row = connection.execute(
                """
                SELECT worker_id, status, cancelled_at
                FROM service_requests
                WHERE id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None or row["worker_id"] != account.account_id:
                raise HTTPException(status_code=404, detail="Booking not found.")
            if row["cancelled_at"] is not None:
                return {"status": "success", "booking_status": "cancelled"}
            raise HTTPException(
                status_code=409,
                detail="Only an accepted booking can be cancelled.",
            )
    return {
        "status": "success",
        "booking_status": "cancelled",
        "message": "Booking cancelled.",
    }


@app.post("/contact")
def create_contact_submission(data: ContactSubmission) -> dict[str, str]:
    name = data.name.strip()
    phone = data.phone_number.strip()
    description = data.description.strip()
    if not name or not phone or not description:
        raise HTTPException(status_code=422, detail="Please fill out all fields.")
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO contact_submissions (name, phone, description, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name, phone, description, timestamp()),
        )
    return {"status": "success", "message": "Your message has been received."}


@app.get("/{file_path:path}", include_in_schema=False)
def frontend_file(file_path: str, request: Request) -> Response:
    candidate = (BASE_DIR / file_path).resolve()
    if candidate.parent != BASE_DIR or candidate.suffix.lower() not in {".html", ".css", ".js", ".mp3"}:
        raise HTTPException(status_code=404, detail="File not found.")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="File not found.")
    required_role = None
    if file_path in USER_ONLY_PAGES:
        required_role = "user"
    elif file_path in WORKER_ONLY_PAGES:
        required_role = "worker"
    if required_role:
        try:
            account = get_current_account(request)
        except HTTPException:
            account = None
        if account is None or account.role != required_role:
            redirect_target = request.url.path
            if request.url.query:
                redirect_target += f"?{request.url.query}"
            login_url = f"/login.html?{urlencode({'redirect': redirect_target})}"
            return RedirectResponse(login_url)
    return FileResponse(candidate)
