from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import psycopg2
import os
import geoip2.database
from datetime import datetime, timezone
from config import Config

router = APIRouter()

# === MMDB setup ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASN_READER = geoip2.database.Reader(os.path.join(BASE_DIR, "GeoLite2-ASN.mmdb"))
CITY_READER = geoip2.database.Reader(os.path.join(BASE_DIR, "GeoLite2-City.mmdb"))
COUNTRY_READER = geoip2.database.Reader(os.path.join(BASE_DIR, "GeoLite2-Country.mmdb"))

def enrich_ip_data(ip: str) -> dict:
    location = {}
    try:
        asn_data = ASN_READER.asn(ip)
        location["asn"] = asn_data.autonomous_system_number
        location["organization"] = asn_data.autonomous_system_organization
    except:
        location["asn"] = None
        location["organization"] = None

    try:
        city_data = CITY_READER.city(ip)
        location.update({
            "city": city_data.city.name,
            "region": city_data.subdivisions.most_specific.name,
            "country": city_data.country.name,
            "latitude": city_data.location.latitude,
            "longitude": city_data.location.longitude,
            "timezone": city_data.location.time_zone,
            "postal_code": city_data.postal.code,
            "continent": city_data.continent.name
        })
    except:
        location.update({
            "city": None, "region": None, "country": None,
            "latitude": None, "longitude": None, "timezone": None,
            "postal_code": None, "continent": None
        })

    try:
        country_data = COUNTRY_READER.country(ip)
        location["iso_country_code"] = country_data.country.iso_code
    except:
        location["iso_country_code"] = None

    return location

# === Request model ===
class LogsAttempt(BaseModel):
    key: str
    user_id: str
    ip: str
    device_fingerprint: str
    success: int  # 0 or 1

# === DB connection ===
def get_db_connection():
    return psycopg2.connect(
        host=Config.POSTGRES_HOST,
        port=Config.POSTGRES_PORT,
        user=Config.POSTGRES_USER,
        password=Config.POSTGRES_PASSWORD,
        dbname=Config.POSTGRES_DB
    )

# === DB + table creation ===
def check_and_create_db():
    # Connect to default database (usually postgres) to check existence of target DB
    conn = psycopg2.connect(
        host=Config.POSTGRES_HOST,
        port=Config.POSTGRES_PORT,
        user=Config.POSTGRES_USER,
        password=Config.POSTGRES_PASSWORD,
        dbname="postgres"  # Connect to default DB
    )
    conn.autocommit = True
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (Config.POSTGRES_DB,))
    if not cursor.fetchone():
        print(f"[BOOT] Creating database {Config.POSTGRES_DB}")
        cursor.execute(f"CREATE DATABASE {Config.POSTGRES_DB}")
    cursor.close()
    conn.close()

def check_and_create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'login_events'
    """)
    if cursor.fetchone()[0] == 0:
        print("[BOOT] Creating table login_events")
        cursor.execute("""
            CREATE TABLE login_events (
                id SERIAL PRIMARY KEY,
                key VARCHAR(255),
                user_id VARCHAR(255),
                ip VARCHAR(45),
                device_fingerprint VARCHAR(255),
                success BOOLEAN,
                timestamp TIMESTAMPTZ,
                city VARCHAR(100),
                region VARCHAR(100),
                country VARCHAR(100),
                continent VARCHAR(100),
                postal_code VARCHAR(20),
                timezone VARCHAR(50),
                latitude DOUBLE PRECISION,
                longitude DOUBLE PRECISION,
                organization VARCHAR(255),
                asn INTEGER,
                iso_country_code VARCHAR(10)
            )
        """)
        conn.commit()
    cursor.close()
    conn.close()

# === Insert + return full payload ===
from datetime import datetime, timezone

def store_event(event: LogsAttempt) -> dict:
    ip_info = enrich_ip_data(event.ip)

    # Use UTC timestamp with timezone info
    timestamp = datetime.now(timezone.utc)  # simpler and explicitly UTC with tzinfo

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_events (
            key, user_id, ip, device_fingerprint, success, timestamp,
            city, region, country, continent, postal_code, timezone,
            latitude, longitude, organization, asn, iso_country_code
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        event.key, event.user_id, event.ip, event.device_fingerprint, bool(event.success), timestamp,
        ip_info.get("city"),
        ip_info.get("region"),
        ip_info.get("country"),
        ip_info.get("continent"),
        ip_info.get("postal_code"),
        ip_info.get("timezone"),
        ip_info.get("latitude"),
        ip_info.get("longitude"),
        ip_info.get("organization"),
        ip_info.get("asn"),
        ip_info.get("iso_country_code")
    ))
    inserted_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "id": inserted_id,
        "timestamp": timestamp.isoformat(),  # ISO8601 with timezone info, good for JSON
        "key": event.key,
        "user_id": event.user_id,
        "ip": event.ip,
        "device_fingerprint": event.device_fingerprint,
        "success": event.success,
    }

# === API route ===
@router.post("/login-logs")
async def log_event(payload: LogsAttempt):
    try:
        check_and_create_db()
        check_and_create_table()
        inserted_data = store_event(payload)
        return inserted_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
