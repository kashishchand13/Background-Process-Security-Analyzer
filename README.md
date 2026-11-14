# Background Process Security Analyzer

A Windows 11 desktop starter project for monitoring process activity and highlighting suspicious indicators. It uses Python, PySide6, psutil, and Oracle Database 21c (including Oracle XE). The interface has a compact, centered, taskbar-inspired navigation dock; it does **not** replace or modify the Windows taskbar.

> Security scope: read-only monitoring and alerting. The app does not terminate processes, modify system services, or claim that a heuristic proves malware. Validate alerts before taking action.

## Features in this starter

1. **Path verification** — checks configured process-name/path reputation rules. Generic processes are not flagged simply because no rule exists.
2. **Process hierarchy analysis** — flags one high-signal heuristic: an Office process launching a command or scripting interpreter. This can be legitimate and needs review.
3. **Resource behavior analysis** — detects CPU/memory values above configurable thresholds.
4. **Reputation matching** — compares process names and executable paths with enabled local rules; supports optional SHA-256 reference hashes.
5. **Process spoofing detection** — separately checks names of selected high-value Windows processes (for example, `svchost.exe` and `lsass.exe`) against their expected direct parent directory. A wrong path is a suspicious indicator, not proof by itself.
6. Live process dashboard, process search/filtering, current CPU/memory/thread/priority/state values, security alerts, process history, and alert investigation status.
7. Optional on-demand hashing only for rules that contain a reference hash; the hash cache avoids repeated reads of unchanged files.

## OS concepts demonstrated

- Process identification and lifecycle: PID, process creation time, first-seen and exit events.
- Parent-child process relationships using PPID.
- Memory management metrics: resident memory and percentage of physical memory.
- CPU/resource management: per-process CPU sampling and threshold analysis.
- Threads and process state.
- Process priority value reported by Windows/psutil. This app observes priority; it does not change the scheduler or priority.

## DBMS concepts demonstrated

- Nine relational tables with primary keys and foreign-key relationships.
- Separation of current process state, historical events, time-series metrics, reputation rules, detection evidence, alerts, and audit actions.
- Unique constraint for process instances (`system_id`, `pid`, `create_time`) because Windows can reuse PIDs.
- Indexes for current-process lookups, reputation matching, metrics history, and alert status.
- Transactional batches for each monitoring scan and parameterized SQL statements.
- JSON evidence stored with each detection result.

## Architecture and low-level design

- `PsutilProcessCollector` — read-only OS collection.
- `SecurityAnalyzer` — coordinates independent detection strategies.
- `DetectionRule` — Strategy-pattern interface; each detector can be added or replaced independently.
- `*Repository` classes — Repository pattern; SQL is isolated from detection and UI code.
- `MonitoringWorker` — Qt worker thread prevents slow OS/DB calls from blocking the UI.
- `AlertManagementService` — service layer coordinates an alert status transaction plus an audit action.
- Dataclasses in `bsa/core/models.py` — typed data transfer objects between layers.
- `Settings` — central configuration/dependency input.

## Database tables (9)

| Table | Responsibility | Key relationships |
|---|---|---|
| `systems` | Monitored computer identity | Parent of sessions and processes |
| `scan_sessions` | One app monitoring run | Belongs to one system; referenced by metrics, history, detections |
| `process_instances` | One process instance, including PID and creation time | Belongs to system; parent of history, metrics, detections |
| `process_history` | First-seen and exit events | References session and process instance |
| `process_metrics` | Periodic resource samples | References session and process instance |
| `reputation_rules` | Local trusted/suspicious/blocklist rules | Used by the analysis engine |
| `detection_results` | Check type, score, verdict, JSON evidence | References session and process instance; parent of an alert |
| `security_alerts` | Alert severity and investigation status | References one detection result |
| `alert_actions` | Audit of status changes | References one alert |

`reputation_rules` has no FK to processes because a rule can exist before a process is observed. That is an intentional reference-data table design.

## Setup on Windows 11

### 1. Install prerequisites

- Python 3.11 (64-bit recommended)
- Oracle Database 21c / Oracle XE with the `XEPDB1` service available, plus SQL*Plus
- Visual C++ runtime if required by your Python installation

### 2. Open PowerShell in this project directory

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Create an Oracle schema user (one-time setup)

Oracle does not use `CREATE DATABASE` / `USE database` in the MySQL sense for this project. Tables are created inside an Oracle schema owned by a user. In SQL*Plus, connect as an administrator to the pluggable database (usually `XEPDB1`) and create a dedicated schema owner. Replace the example password with one of your own:

```sql
CONNECT SYSTEM@localhost:1521/XEPDB1
CREATE USER BSA IDENTIFIED BY "Choose_A_Strong_Password";
GRANT CREATE SESSION, CREATE TABLE TO BSA;
ALTER USER BSA QUOTA UNLIMITED ON USERS;
```

If the `BSA` user already exists, do not run `CREATE USER` again; grant the needed privileges and quota to the existing user instead.

### 4. Configure Oracle connection settings

Set these environment variables in the same PowerShell window. Avoid committing credentials to Git.

```powershell
$env:BSA_DB_HOST = "127.0.0.1"
$env:BSA_DB_PORT = "1521"
$env:BSA_DB_SERVICE_NAME = "XEPDB1"
$env:BSA_DB_USER = "BSA"
$env:BSA_DB_PASSWORD = "Choose_A_Strong_Password"
```

Use the service name shown by your Oracle installation if it is not `XEPDB1`. The Python `oracledb` driver uses its Thin mode by default, so Oracle Instant Client is not normally required.

### 5. Create the nine tables

**Option A — use SQL*Plus:** From the project directory, run SQL*Plus as the `BSA` schema owner, then execute the schema file:

```sql
CONNECT BSA@localhost:1521/XEPDB1
@database/schema.sql
```

**Option B — use the Python setup script:** With the environment variables set, run:

```powershell
python setup_db.py
```

Both methods create the tables and indexes without dropping existing data. The Python setup script skips objects that already exist, but it does not migrate an old table to a changed structure; review schema changes separately.

### 6. Start the desktop application

```powershell
python app.py
```

Allow a few polling cycles for CPU samples to become meaningful. Some process paths or usernames may be unavailable due to Windows access restrictions. Run normally first; only elevate privileges if you need additional visibility and understand the implications.

## Add a local reputation rule

Add a rule in SQL*Plus while connected as the `BSA` schema owner. Paths should be based on your own trusted software and verified from the machine; do not blindly trust process names.

```sql
INSERT INTO reputation_rules
(process_name, expected_path_prefix, sha256_hash, reputation, reason, is_enabled)
VALUES
('example.exe', 'C:\Program Files\Example', NULL,
 'TRUSTED', 'Locally verified example application', 'Y');
COMMIT;
```

If a SHA-256 hash is supplied, the analyzer checks that hash only when it evaluates a matching rule. Very large files and inaccessible files may not be hashed. This starter does not yet validate Authenticode digital signatures.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The detector tests cover path boundaries, process spoofing, hierarchy heuristics, and resource thresholds. They do not require a database connection.

## Build a Windows executable

First test the app from Python. Then run:

```powershell
pyinstaller --noconfirm --clean --windowed --name BackgroundProcessSecurityAnalyzer app.py
```

The default command creates `dist\BackgroundProcessSecurityAnalyzer\BackgroundProcessSecurityAnalyzer.exe`. The target machine still needs access to the configured Oracle database service. A one-file executable does not bundle the database service. For a distributable product, add a proper installer, signing, credential setup, database migrations, retention management, and more thorough test coverage.

## Known limits and next steps

- This is an educational rule-based analyzer, not a replacement for Microsoft Defender or an endpoint detection product.
- The starter supports local reputation rules; it does not query an online threat-intelligence service.
- The default rules cover only selected Windows process names and path locations. A valid Windows process may run from another legitimate location on some installations.
- Resource spikes and Office-to-script relationships can be legitimate. Treat them as investigative signals, not confirmed malware.
- Metrics are sampled for the top N processes every configured interval to reduce database growth. Adjust `BSA_METRICS_INTERVAL` and `BSA_METRICS_TOP_N` for your test machine.
- Process first-seen history is recorded for processes observed during the running session; this app does not install a Windows service or persist before the application starts.
- Before a real deployment, add retention/purge jobs, robust migration tooling, signed executable checks, unit/integration tests on Windows, and a least-privilege deployment design.
