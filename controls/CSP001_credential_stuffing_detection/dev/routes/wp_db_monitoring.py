import asyncio
from datetime import datetime, timezone, timedelta
import os
import psycopg2
import psycopg2.extras
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from geopy.distance import geodesic
from config import Config
from controls.ws.websocket_manager import ws_manager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_FILE = os.path.join(BASE_DIR, "wp_monitor_checkpoint.txt")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Accept from all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def read_checkpoint() -> datetime:
    """Read checkpoint timestamp from file as UTC datetime with tzinfo."""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f:
                ts_str = f.read().strip()
                return datetime.fromisoformat(ts_str)
        except Exception as e:
            print(f"Error reading checkpoint file: {e}")

    # Fallback: get max timestamp from DB or current UTC time
    try:
        with psycopg2.connect(
            host=Config.POSTGRES_HOST,
            port=Config.POSTGRES_PORT,
            user=Config.POSTGRES_USER,
            password=Config.POSTGRES_PASSWORD,
            database=Config.POSTGRES_DB
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT MAX(timestamp) FROM login_events")
                result = cursor.fetchone()
                max_ts = result[0]
                if max_ts is None:
                    return datetime.now(timezone.utc)
                if max_ts.tzinfo is None:
                    max_ts = max_ts.replace(tzinfo=timezone.utc)
                return max_ts
    except psycopg2.Error as e:
        print(f"Database error during checkpoint read: {e}")
        return datetime.now(timezone.utc)

def write_checkpoint(timestamp: datetime):
    """Write checkpoint timestamp as ISO8601 string with tzinfo."""
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(timestamp.isoformat())

def calculate_risk_from_timestamps(user_id, ip, device_fingerprint, start_ts: datetime, end_ts: datetime,
                                   time_window_sec=60, success_threshold=5) -> int:
    try:
        with psycopg2.connect(
            host=Config.POSTGRES_HOST,
            port=Config.POSTGRES_PORT,
            user=Config.POSTGRES_USER,
            password=Config.POSTGRES_PASSWORD,
            database=Config.POSTGRES_DB
        ) as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT user_id, ip, device_fingerprint, timestamp, success, latitude, longitude
                    FROM login_events
                    WHERE timestamp BETWEEN %s AND %s
                """, (start_ts, end_ts))

                events = cursor.fetchall()

        # Filter attack IP events
        attack_events = [e for e in events if e['ip'] == ip]

        # Failed and successful attempts by user at attack IP
        failed_attempts = [e for e in attack_events if not e['success'] and e['user_id'] == user_id]
        successful_attempts = [e for e in attack_events if e['success'] and e['user_id'] == user_id]

        # Detect burst of successes in time_window_sec
        success_events = sorted(successful_attempts, key=lambda x: x['timestamp'].timestamp())
        burst_detected = False
        for i in range(len(success_events)):
            window_start = success_events[i]['timestamp'].timestamp()
            count = 1
            for j in range(i+1, len(success_events)):
                if success_events[j]['timestamp'].timestamp() <= window_start + time_window_sec:
                    count += 1
                else:
                    break
            if count >= success_threshold:
                burst_detected = True
                break

        # Unique users reusing device fingerprint
        device_reuse_users = {e['user_id'] for e in events if e['device_fingerprint'] == device_fingerprint}

        # Unique IPs used by this user
        ips_in_attack = {e['ip'] for e in events if e['user_id'] == user_id}

        # Location anomaly detection
        location_anomaly_distance_km = 500
        location_anomaly_time_min = 60

        events_sorted = sorted([e for e in events if e['timestamp'] is not None], key=lambda x: x['timestamp'])
        location_anomalies = []

        for i in range(1, len(events_sorted)):
            prev_event = events_sorted[i-1]
            curr_event = events_sorted[i]
            time_diff_min = (curr_event['timestamp'] - prev_event['timestamp']).total_seconds() / 60
            if time_diff_min <= location_anomaly_time_min:
                prev_lat = prev_event.get('latitude')
                prev_lon = prev_event.get('longitude')
                curr_lat = curr_event.get('latitude')
                curr_lon = curr_event.get('longitude')

                if None not in (prev_lat, prev_lon, curr_lat, curr_lon):
                    dist_km = geodesic((prev_lat, prev_lon), (curr_lat, curr_lon)).kilometers
                    if dist_km > location_anomaly_distance_km:
                        location_anomalies.append({
                            "from_event": prev_event,
                            "to_event": curr_event,
                            "distance_km": dist_km,
                            "time_diff_min": time_diff_min,
                            "note": f"Impossible travel detected: {dist_km:.1f} km in {time_diff_min:.1f} minutes"
                        })

        risk_score = 0
        if len(failed_attempts) > 5:
            risk_score += 30
        if len(attack_events) > 5:
            risk_score += 20
        if len(device_reuse_users) > 3:
            risk_score += 10
        if len(ips_in_attack) > 1:
            risk_score += 20
        if location_anomalies:
            risk_score += 10
        if burst_detected:
            risk_score += 10

        return risk_score

    except psycopg2.Error as e:
        print(f"Database error in risk calculation: {e}")
        return 0

async def monitor_db_credential_stuffing_detection():
    print("Starting credential stuffing DB monitoring...")
    check_interval_seconds = 5
    alert_cooldown_seconds = 300  # 5 minutes cooldown
    last_alert_times = {}  # {(user_id, ip, key): datetime}

    while True:
        last_checked = read_checkpoint()
        now = datetime.now(timezone.utc)

        try:
            with psycopg2.connect(
                host=Config.POSTGRES_HOST,
                port=Config.POSTGRES_PORT,
                user=Config.POSTGRES_USER,
                password=Config.POSTGRES_PASSWORD,
                database=Config.POSTGRES_DB
            ) as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT DISTINCT id, key, user_id, ip, device_fingerprint, success, timestamp,
                           city, region, country, continent, postal_code, timezone,
                           latitude, longitude, organization, asn, iso_country_code
                        FROM login_events
                        WHERE timestamp > %s AND timestamp <= %s
                        ORDER BY timestamp ASC
                    """, (last_checked, now))
                    events = cursor.fetchall()

            max_timestamp_processed = last_checked

            for event in events:
                user_id = event['user_id']
                ip = event['ip']
                device_fp = event['device_fingerprint']
                key = event.get('session_key') or event.get('key') or "default_key"
                event_ts = event['timestamp']  # datetime object with tzinfo

                window_start = event_ts - timedelta(minutes=5)
                risk_score = calculate_risk_from_timestamps(user_id, ip, device_fp, window_start, event_ts)

                alert_key = (user_id, ip, key)
                now_ts = datetime.now(timezone.utc)

                last_alert = last_alert_times.get(alert_key, datetime.fromtimestamp(0, tz=timezone.utc))
                if risk_score >= 5 and (now_ts - last_alert).total_seconds() > alert_cooldown_seconds:
                    alert_msg = {
                        "status": "ALERT",
                        "cata": "detect-cred-stuff",
                        "risk_score": risk_score,
                        "user_id": user_id,
                        "device_fingerprint": device_fp,
                        "ip": ip,
                        "key": key,
                        "timestamp": event_ts.isoformat()
                    }
                    print(f"alert_msg: {alert_msg}")
                    await ws_manager.send_message(key, alert_msg)
                    print(f"Alert sent for user {user_id}, key {key}")

                    last_alert_times[alert_key] = now_ts

                if event_ts > max_timestamp_processed:
                    max_timestamp_processed = event_ts

            write_checkpoint(max_timestamp_processed)

        except psycopg2.Error as e:
            print(f"Database connection error during monitoring: {e}")

        await asyncio.sleep(check_interval_seconds)

__all__ = ["monitor_db_credential_stuffing_detection"]
