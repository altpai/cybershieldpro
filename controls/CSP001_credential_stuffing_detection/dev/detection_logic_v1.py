from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import psycopg2
from config import Config
import asyncio
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from geopy.distance import geodesic
from dateutil.parser import isoparse
from controls.CSP001_credential_stuffing_detection.genai.narrative_generator import generate_narrative

router = APIRouter()

# ---------- Request Payload ----------
class RiskDetectionPayload(BaseModel):
    key: str
    start_date: Optional[str] = None  # ISO format, e.g. "2025-07-30T00:00:00Z"
    end_date: Optional[str] = None

# ---------- Full Login Event Model ----------
class LoginEvent(BaseModel):
    id: Optional[int] = None
    key: Optional[str] = None
    user_id: Optional[str] = None
    ip: Optional[str] = None
    device_fingerprint: Optional[str] = None
    success: Optional[int] = None
    timestamp: Optional[int] = None  # UNIX timestamp in seconds
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    continent: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    organization: Optional[str] = None
    asn: Optional[int] = None
    iso_country_code: Optional[str] = None

def fetch_events_for_key_timeframe(key: str, window_start: datetime, window_end: datetime) -> List[LoginEvent]:
    """
    Fetch login events for a given key within a datetime window.
    Note: window_start and window_end are timezone-aware datetime objects in UTC.
    """
    try:
        with psycopg2.connect(
            host=Config.POSTGRES_HOST,
            port=Config.POSTGRES_PORT,
            user=Config.POSTGRES_USER,
            password=Config.POSTGRES_PASSWORD,
            database=Config.POSTGRES_DB
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, key, user_id, ip, device_fingerprint, success,
                           EXTRACT(EPOCH FROM timestamp) AS timestamp,
                           city, region, country, continent, postal_code, timezone,
                           latitude, longitude, organization, asn, iso_country_code
                    FROM login_events
                    WHERE key = %s
                      AND timestamp BETWEEN %s AND %s
                    ORDER BY user_id, timestamp
                """, (key, window_start, window_end))

                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()

                events = []
                for row in rows:
                    data = dict(zip(columns, row))
                    if data.get('timestamp') is not None:
                        data['timestamp'] = int(data['timestamp'])
                    events.append(LoginEvent(**data))
                return events

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# ---------- Risk Grouping with narrative per attack ----------
async def calculate_risks_grouped(
    key: str,
    window_start: datetime,
    window_end: datetime,
    success_threshold: int = 5,
    time_window_sec: int = 300,
    location_anomaly_distance_km: float = 500.0,
    location_anomaly_time_min: int = 60
) -> Dict[str, Any]:

    all_events = fetch_events_for_key_timeframe(key, window_start, window_end)
    users = defaultdict(list)
    for event in all_events:
        users[event.user_id].append(event)

    grouped_results = {}

    for user_id, events in users.items():
        attacks = []
        all_user_ips = set()
        attack_groups = defaultdict(list)

        events_sorted = sorted(events, key=lambda e: e.timestamp or 0)

        # Location anomaly detection — impossible travel detection
        location_anomalies = []
        for i in range(1, len(events_sorted)):
            prev_event = events_sorted[i-1]
            curr_event = events_sorted[i]
            if prev_event.timestamp is None or curr_event.timestamp is None:
                continue

            time_diff_min = (curr_event.timestamp - prev_event.timestamp) / 60
            if time_diff_min <= location_anomaly_time_min:
                if prev_event.latitude is not None and prev_event.longitude is not None and \
                   curr_event.latitude is not None and curr_event.longitude is not None:
                    dist_km = geodesic(
                        (prev_event.latitude, prev_event.longitude),
                        (curr_event.latitude, curr_event.longitude)
                    ).kilometers
                    if dist_km > location_anomaly_distance_km:
                        location_anomalies.append({
                            "from_event": prev_event.dict(),
                            "to_event": curr_event.dict(),
                            "distance_km": dist_km,
                            "time_diff_min": time_diff_min,
                            "note": f"Impossible travel detected: {dist_km:.1f} km in {time_diff_min:.1f} minutes"
                        })

        # Group events by (IP, device fingerprint)
        for e in events:
            attack_key = (e.ip, e.device_fingerprint)
            attack_groups[attack_key].append(e)
            all_user_ips.add(e.ip)

        for (_, device_fp), attack_events in attack_groups.items():
            failed_attempts = [a for a in attack_events if a.success == 0]
            successful_attempts = [a for a in attack_events if a.success == 1]
            device_reuse_users = set(a.user_id for a in attack_events)

            ips_in_attack = sorted(set(a.ip for a in attack_events))

            risk_score = 0

            if len(failed_attempts) > 5:
                risk_score += 30

            if len(attack_events) > 5:
                risk_score += 20

            if len(device_reuse_users) > 3:
                risk_score += 10

            if len(ips_in_attack) > 1:
                risk_score += 20

            if len(location_anomalies) > 0:
                risk_score += 10

            success_events = sorted(successful_attempts, key=lambda x: x.timestamp or 0)
            for i in range(len(success_events)):
                window_start_time = success_events[i].timestamp or 0
                count = 1
                for j in range(i + 1, len(success_events)):
                    if success_events[j].timestamp and success_events[j].timestamp <= window_start_time + time_window_sec:
                        count += 1
                    else:
                        break
                if count >= success_threshold:
                    risk_score += 10
                    break

            attack_dict = {
                "status": "ALERT" if risk_score >= 2 else "OK",
                "risk_score": risk_score,
                "ip": ips_in_attack,
                "device_fingerprint": device_fp,
                "event_timestamp": attack_events[0].timestamp,
                "detection_evidence": {
                    "failed_attempts": [a.dict() for a in failed_attempts],
                    "successful_attempts": [a.dict() for a in successful_attempts],
                    "ip_velocity": [a.dict() for a in attack_events],
                    "device_reuse": [a.dict() for a in attack_events],
                    "location_anomalies": location_anomalies  
                }
            }

            try:
                narrative_data = await asyncio.to_thread(generate_narrative, attack_dict)
                attack_dict.update({
                    "native_narrative": narrative_data.get("narrative", ""),
                    "recommendation": narrative_data.get("recommendation", ""),
                    "localization_tags": narrative_data.get("localization_tags", None)
                })
            except Exception as e:
                attack_dict.update({
                    "native_narrative": "",
                    "recommendation": "",
                    "localization_tags": None,
                    "narrative_error": str(e)
                })

            if not (attack_dict["status"] == "OK" and attack_dict["risk_score"] == 0):
                attacks.append(attack_dict)

        total_user_risk_score = sum(a['risk_score'] for a in attacks)
        if len(all_user_ips) > 1:
            total_user_risk_score += 2

        grouped_results[user_id] = {
            "attacks": attacks
        }

    return grouped_results

# ---------- Endpoint ----------
@router.post("/detect-cred-stuff")
async def detect_by_key(payload: RiskDetectionPayload):
    if payload.start_date and payload.end_date:
        try:
            start_dt = isoparse(payload.start_date)
            end_dt = isoparse(payload.end_date)

            # Ensure timezone-aware UTC datetimes
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            else:
                start_dt = start_dt.astimezone(timezone.utc)

            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            else:
                end_dt = end_dt.astimezone(timezone.utc)

        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid date format. Use ISO 8601 with timezone (e.g. 2025-07-30T00:00:00Z). Error: {str(e)}"
            )
    else:
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=1)
        end_dt = now

    # Pass datetime objects directly (not Unix timestamps)
    grouped_data = await calculate_risks_grouped(payload.key, start_dt, end_dt)

    users_response = []
    for user_id, data in grouped_data.items():
        if not isinstance(data, dict) or "attacks" not in data:
            continue
        users_response.append({
            "user_id": user_id,
            "attacks": data["attacks"]
        })

    return {
        "key": payload.key,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "users": users_response,
    }
