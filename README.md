# Employee Account Lifecycle Automation

Author: Elyas Ghwiet - Yuva virtual internship (IT / Network Support), Week 3

A Python script that keeps a user directory in step with HR events. HR sends a CSV of joiners, leavers and movers; the script creates, disables and updates accounts, assigns groups from a department policy, and writes an audit log and a report. It is written for the IT task "user account management" and uses only the Python standard library.

## Why this task

Creating accounts for new staff and disabling them for leavers is repetitive, error-prone and security-critical. A forgotten leaver account is a real risk, and manual username choices lead to duplicates. The script turns the HR file into the single source of truth and makes every change traceable.

## Features

| Feature | What it does |
|---|---|
| Joiner / mover / leaver events | `HIRE`, `TRANSFER`, `TERMINATE` rows in one CSV |
| Username generation | first initial + surname, ASCII only, unique (`ahassan`, `ahassan2`) |
| Arabic names | transliterated automatically; an optional `latin_name` column overrides it |
| Department policy | groups per department in `data/policy.json`; unknown departments are rejected |
| Temporary passwords | random, 14 characters, stored only as a PBKDF2 hash; the plain text goes to a separate credentials file |
| Safe leaver handling | accounts are disabled, not deleted; groups removed, password invalidated; deletion only after the retention period and only with `--purge` |
| Deferred events | events dated after the run date wait for a later run (pre-boarding) |
| Idempotent | running the same file again changes nothing |
| Dry run | `--dry-run` previews a run and writes nothing |
| Audit trail | `output/audit.log` (append-only), a report per run, credentials file per run |
| Robust errors | a bad row is rejected with a reason and the rest of the file is still processed; file-level problems stop the run with exit code 2 and never damage the directory |
| Safe writes | directory is written atomically and the previous version is kept as `.bak` |

## Requirements

Python 3.8 or newer. `pip install pytest` is only needed to run the tests.

## Quick start

```
python account_automation.py --hr data/hr_day1.csv --as-of 2026-11-01 --dry-run
python account_automation.py --hr data/hr_day1.csv --as-of 2026-11-01
python account_automation.py --hr data/hr_day2.csv --as-of 2026-11-15
python -m pytest -v
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--hr FILE` | required | HR events CSV |
| `--directory FILE` | `data/directory.json` | simulated user directory |
| `--policy FILE` | `data/policy.json` | departments, groups, retention days |
| `--out-dir DIR` | `output` | audit log, reports, credentials |
| `--as-of YYYY-MM-DD` | today | run date; later events are deferred |
| `--dry-run` | off | show the result, change nothing |
| `--purge` | off | delete accounts disabled longer than `retention_days` |

## HR file format

UTF-8 CSV (an Excel "CSV UTF-8" export with BOM is fine). Required columns: `employee_id, full_name, department, event, effective_date`. Optional: `latin_name`. Dates are `YYYY-MM-DD`.

```
employee_id,full_name,department,event,effective_date,latin_name
E1001,Elyas Ghwiet,IT,HIRE,2026-11-01,
E1003,محمد الحربي,Finance,HIRE,2026-11-01,Mohammed Alharbi
E1005,Ali Hassan,Finance,TRANSFER,2026-11-10,
E1002,Sara Al-Harbi,HR,TERMINATE,2026-11-12,
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | all rows processed |
| 1 | run completed but at least one row was rejected |
| 2 | fatal error (missing file, missing column, corrupt directory, invalid policy, bad `--as-of`) |

## Folder contents

| Path | Description |
|---|---|
| `account_automation.py` | the script |
| `data/` | policy and sample HR files (day 1, day 2, a file with deliberate errors) |
| `tests/test_account_automation.py` | 41 pytest tests |
| `sample_output/` | console output of every demo scenario, audit log and final directory |
| `screenshots/` | execution screenshots used in the report |
| `report/` | the PDF report |

## Scheduling

The script needs no interaction, so it can run daily: Windows Task Scheduler (`python account_automation.py --hr <path>`) or `cron` on Linux. The exit code tells the scheduler whether anything was rejected.

## Limitations and next steps

The directory is a JSON file so the script can be tested without administrator rights. In production, the `DirectoryStore` class would be replaced by calls to Active Directory / LDAP or `net user` / `useradd`. Temporary passwords should be delivered through a secure channel and the credentials file deleted after use.
