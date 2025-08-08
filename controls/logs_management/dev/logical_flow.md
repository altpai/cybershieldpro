# Credential Stuffing Detection System – Logical Flow Documentation

This document details the end-to-end logic, data flow, and internal mechanisms of the credential stuffing detection system using **FastAPI**, **MySQL**, **WebSockets**, and **async monitoring**.

---

## Overview of System Components

| Component           | Description                                                         |
|-------------------- |---------------------------------------------------------------------|
| `/login-logs`       | Stores login logs                                                   |
| `/request-logs`     | Stores all requests logs                                            |


---

## Logical Flow by Route / Module

---


### `/login-logs`

**Purpose**: Store login attempt 
**Method**: `POST`  

#### Flow:

1. Ensure DB and `login_events` table exist.
2. Save login attempt to DB.


---------------------------------------



### `/request-logs`

**Purpose**: Store requests logs 
**Method**: `POST`  

#### Flow:

1. Ensure DB and `request_logs` table exist.
2. Save login attempt to DB.
