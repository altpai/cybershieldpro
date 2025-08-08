# Credential Stuffing Detection System – Logical Flow Documentation


## Overview of System Components

| Component           | Description                                                        |
|--------------------|---------------------------------------------------------------------|
| `/detect-cred-stuff` | Calculates risk score using provided login window (no storage)    |

---

## Logical Flow by Route / Module

---

### `/detect-cred-stuff`

**Purpose**: Risk evaluation of a login attempt based on historical data  
**Method**: `POST`  
**Input**: JSON body (`LoginAttempt` schema)  
**Output**: Risk score and status

#### Flow:

1. Client sends login attempt with a time window (`start_date`, `end_date`).
2. Endpoint converts dates to timestamps.
3. Risk is calculated:
    - Failed login attempts by user/IP.
    - Login volume from IP (velocity).
    - Device reuse across users.
4. Score thresholds applied:
    - `risk >= 2 → ALERT`
    - else `OK`
5. Returns status and risk score.

