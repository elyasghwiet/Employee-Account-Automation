#!/usr/bin/env python3
"""Employee Account Lifecycle Automation.

Reads a CSV of HR events (HIRE, TERMINATE, TRANSFER) and keeps a (simulated) user
directory in step with it:

* HIRE      -> create an account (or re-enable a disabled one), generate a unique
               username, assign groups from the department policy, issue a temporary password
* TERMINATE -> disable the account, remove its groups, invalidate the password
* TRANSFER  -> move the account to the new department's groups

Every run writes an audit log and a report. The script is idempotent: running the same
HR file twice changes nothing the second time. Use --dry-run to preview a run.

Only the Python standard library is used. The directory is a JSON file, so the script can be
tested without administrator rights; the DirectoryStore class is the single place that would
be replaced by real calls (net user, useradd, LDAP) in a production deployment.
"""
import argparse
import csv
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import string
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timedelta

EXIT_OK, EXIT_REJECTED, EXIT_FATAL = 0, 1, 2
REQUIRED_COLUMNS = ["employee_id", "full_name", "department", "event", "effective_date"]
EVENTS = ("HIRE", "TERMINATE", "TRANSFER")
EMPLOYEE_ID_RE = re.compile(r"^[A-Za-z0-9-]{3,20}$")
USERNAME_MAX = 20
PBKDF2_ROUNDS = 200_000

log = logging.getLogger("account_automation")

# Approximate Arabic -> Latin transliteration so that HR files written in Arabic still
# produce ASCII usernames. A latin_name column in the HR file always takes precedence.
AR_MAP = {
    "ا": "a", "أ": "a", "إ": "i", "آ": "a", "ب": "b", "ت": "t", "ث": "th", "ج": "j", "ح": "h",
    "خ": "kh", "د": "d", "ذ": "dh", "ر": "r", "ز": "z", "س": "s", "ش": "sh", "ص": "s", "ض": "d",
    "ط": "t", "ظ": "z", "ع": "a", "غ": "gh", "ف": "f", "ق": "q", "ك": "k", "ل": "l", "م": "m",
    "ن": "n", "ه": "h", "و": "w", "ي": "y", "ى": "a", "ة": "a", "ء": "", "ئ": "y", "ؤ": "w",
}


class RowError(Exception):
    """A single HR row is invalid; the row is rejected and the run continues."""


class FatalError(Exception):
    """The run cannot continue (missing file, corrupt directory, bad policy)."""


@dataclass
class Result:
    line: int
    employee_id: str
    action: str
    status: str
    username: str = ""
    detail: str = ""


# ----------------------------------------------------------------------------- names
def to_ascii_words(name):
    """Return the lower-case ASCII words of a name (Arabic letters are transliterated)."""
    out = []
    for original in name:
        if original in AR_MAP:                                      # map Arabic before normalising
            out.append(AR_MAP[original])
            continue
        for ch in unicodedata.normalize("NFKD", original):          # strips accents: José -> jose
            if unicodedata.combining(ch):
                continue
            if ch.isascii() and ch.isalnum():
                out.append(ch.lower())
            elif ch.isspace():
                out.append(" ")                                     # other characters (-, ', digits-less symbols) are dropped
    return "".join(out).split()


def base_username(name, max_len=USERNAME_MAX):
    words = to_ascii_words(name)
    if not any(ch.isalpha() for w in words for ch in w):
        raise RowError("name has no usable letters for a username")
    first, last = words[0], words[-1]
    return (first[0] + last if len(words) > 1 else first)[:max_len]


def unique_username(base, taken):
    """base, base2, base3, ... - names of disabled accounts stay taken (audit trail)."""
    if base not in taken:
        return base
    n = 2
    while "%s%d" % (base[:USERNAME_MAX - len(str(n))], n) in taken:
        n += 1
    return "%s%d" % (base[:USERNAME_MAX - len(str(n))], n)


# ------------------------------------------------------------------------- passwords
def new_temp_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%&*" for c in pw)):
            return pw


def hash_password(pw):
    salt = secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), PBKDF2_ROUNDS).hex()
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ROUNDS, salt, digest)


# ------------------------------------------------------------------------ directory
class DirectoryStore:
    """Simulated user directory kept in a JSON file (replace this class for a real system)."""

    def __init__(self, path):
        self.path = path
        self.data = {"version": 1, "users": {}}

    def load(self):
        if not os.path.exists(self.path):
            log.info("Directory %s does not exist yet - starting with an empty directory", self.path)
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
                raise ValueError("missing 'users' object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise FatalError("Directory file %s is corrupt (%s). It was NOT modified; restore a "
                             "good copy (%s.bak if it exists) and run again." % (self.path, exc, self.path))
        self.data = data

    def save(self):
        """Write atomically and keep one backup of the previous version."""
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        if os.path.exists(self.path):
            shutil.copy2(self.path, self.path + ".bak")
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    @property
    def users(self):
        return self.data["users"]

    def find_by_employee(self, employee_id):
        for username, u in self.users.items():
            if u["employee_id"] == employee_id:
                return username, u
        return None, None


# --------------------------------------------------------------------------- policy
def load_policy(path):
    try:
        with open(path, encoding="utf-8") as f:
            pol = json.load(f)
    except FileNotFoundError:
        raise FatalError("Policy file not found: %s" % path)
    except json.JSONDecodeError as exc:
        raise FatalError("Policy file %s is not valid JSON (%s)" % (path, exc))
    if not isinstance(pol.get("departments"), dict) or not pol["departments"]:
        raise FatalError("Policy file %s must define a non-empty 'departments' object" % path)
    pol.setdefault("default_groups", [])
    pol.setdefault("retention_days", 30)
    pol["_dept_lookup"] = {k.lower(): k for k in pol["departments"]}
    return pol


def groups_for(policy, department):
    return sorted(set(policy["default_groups"]) | set(policy["departments"][department]))


# ------------------------------------------------------------------------- HR input
def read_hr_file(path):
    """Return a list of (line_number, row_dict). Raises FatalError for file-level problems."""
    if not os.path.exists(path):
        raise FatalError("HR file not found: %s" % path)
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:   # utf-8-sig: Excel adds a BOM
            reader = csv.DictReader(f)
            header = [h.strip() for h in (reader.fieldnames or [])]
            missing = [c for c in REQUIRED_COLUMNS if c not in header]
            if missing:
                raise FatalError("HR file %s is missing required column(s): %s" % (path, ", ".join(missing)))
            rows = []
            for row in reader:
                clean = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
                if not any(clean.values()):
                    continue                                       # skip blank lines
                rows.append((reader.line_num, clean))
            return rows
    except UnicodeDecodeError:
        raise FatalError("HR file %s is not valid UTF-8; save it as 'CSV UTF-8' from Excel" % path)


def validate_row(row, policy):
    employee_id = row["employee_id"]
    if not EMPLOYEE_ID_RE.match(employee_id):
        raise RowError("invalid employee_id %r (3-20 letters, digits or '-')" % employee_id)
    if not row["full_name"] or len(row["full_name"]) > 80:
        raise RowError("full_name is empty or longer than 80 characters")
    event = row["event"].upper()
    if event not in EVENTS:
        raise RowError("unknown event %r (expected %s)" % (row["event"], "/".join(EVENTS)))
    try:
        eff = datetime.strptime(row["effective_date"], "%Y-%m-%d").date()
    except ValueError:
        raise RowError("effective_date %r is not in YYYY-MM-DD format" % row["effective_date"])
    dept = policy["_dept_lookup"].get(row["department"].lower())
    if dept is None:
        raise RowError("unknown department %r (policy knows: %s)"
                       % (row["department"], ", ".join(sorted(policy["departments"]))))
    return {"employee_id": employee_id, "full_name": row["full_name"], "event": event,
            "effective": eff, "department": dept, "latin_name": row.get("latin_name", "")}


# ---------------------------------------------------------------------- the actions
def apply_event(ev, store, policy, as_of, credentials):
    """Apply one validated event to the directory. Returns (status, username, detail)."""
    username, user = store.find_by_employee(ev["employee_id"])
    action, dept = ev["event"], ev["department"]

    if action == "HIRE":
        if user and user["status"] == "active":
            return "SKIPPED", username, "already has an active account"
        pw = new_temp_password()
        if user:                                                    # re-hire of a disabled account
            user.update(status="active", department=dept, groups=groups_for(policy, dept),
                        disabled_on=None, password_hash=hash_password(pw), must_change_password=True)
            credentials.append((username, pw))
            return "ENABLED", username, "re-hire: account re-enabled in %s" % dept
        base = base_username(ev["latin_name"] or ev["full_name"])
        username = unique_username(base, set(store.users))
        store.users[username] = {
            "employee_id": ev["employee_id"], "full_name": ev["full_name"], "department": dept,
            "status": "active", "groups": groups_for(policy, dept), "created": as_of.isoformat(),
            "disabled_on": None, "password_hash": hash_password(pw), "must_change_password": True}
        credentials.append((username, pw))
        note = "" if username == base else " (%s was taken)" % base
        return "CREATED", username, "department %s, groups %s%s" % (dept, ", ".join(store.users[username]["groups"]), note)

    if user is None:
        raise RowError("no account exists for employee %s" % ev["employee_id"])

    if action == "TERMINATE":
        if user["status"] == "disabled":
            return "SKIPPED", username, "account already disabled"
        user.update(status="disabled", groups=[], disabled_on=ev["effective"].isoformat(),
                    password_hash=None, must_change_password=False)
        return "DISABLED", username, "groups removed, password invalidated"

    if action == "TRANSFER":
        if user["status"] != "active":
            raise RowError("cannot transfer: account %s is disabled" % username)
        if user["department"] == dept:
            return "SKIPPED", username, "already in %s" % dept
        old = user["department"]
        user.update(department=dept, groups=groups_for(policy, dept))
        return "UPDATED", username, "moved %s -> %s, groups %s" % (old, dept, ", ".join(user["groups"]))
    raise RowError("unsupported event %s" % action)               # not reachable after validation


def purge_candidates(store, policy, as_of):
    limit = as_of - timedelta(days=int(policy["retention_days"]))
    return sorted(u for u, rec in store.users.items()
                  if rec["status"] == "disabled" and rec.get("disabled_on")
                  and date.fromisoformat(rec["disabled_on"]) <= limit)


# --------------------------------------------------------------------------- the run
def run(hr_path, dir_path, policy_path, out_dir, as_of, dry_run=False, purge=False):
    """Process one HR file. Returns (results, credentials). Raises FatalError."""
    policy = load_policy(policy_path)
    rows = read_hr_file(hr_path)
    store = DirectoryStore(dir_path)
    store.load()

    results, credentials, events = [], [], []
    for line, row in rows:
        try:
            ev = validate_row(row, policy)
            ev["line"] = line
            events.append(ev)
        except RowError as exc:
            results.append(Result(line, row.get("employee_id", ""), row.get("event", "").upper(), "REJECTED", "", str(exc)))

    events.sort(key=lambda e: (e["effective"], e["line"]))        # apply in date order
    for ev in events:
        if ev["effective"] > as_of:
            results.append(Result(ev["line"], ev["employee_id"], ev["event"], "DEFERRED", "",
                                  "effective %s is after run date %s" % (ev["effective"], as_of)))
            continue
        try:
            status, username, detail = apply_event(ev, store, policy, as_of, credentials)
            results.append(Result(ev["line"], ev["employee_id"], ev["event"], status, username, detail))
        except RowError as exc:
            results.append(Result(ev["line"], ev["employee_id"], ev["event"], "REJECTED", "", str(exc)))

    for username in purge_candidates(store, policy, as_of):
        if purge:
            del store.users[username]
            results.append(Result(0, "", "PURGE", "PURGED", username, "disabled longer than %s days" % policy["retention_days"]))
        else:
            results.append(Result(0, "", "PURGE", "PURGE_DUE", username,
                                  "disabled longer than %s days - run with --purge to delete" % policy["retention_days"]))

    results.sort(key=lambda r: (r.line == 0, r.line))
    if not dry_run:
        write_outputs(store, results, credentials, hr_path, out_dir, as_of)
    return results, credentials


def write_outputs(store, results, credentials, hr_path, out_dir, as_of):
    os.makedirs(out_dir, exist_ok=True)
    stamp = "%s_%s" % (as_of.isoformat(), datetime.now().strftime("%H%M%S"))   # never overwrite an earlier run
    changed = any(r.status in ("CREATED", "ENABLED", "DISABLED", "UPDATED", "PURGED") for r in results)
    if changed or not os.path.exists(store.path):
        store.save()
    with open(os.path.join(out_dir, "audit.log"), "a", encoding="utf-8") as f:
        for r in results:
            f.write("%s | %-9s | %-10s | %-8s | %-14s | %s\n" % (
                datetime.now().isoformat(timespec="seconds"), r.status, r.action, r.employee_id or "-", r.username or "-", r.detail))
    with open(os.path.join(out_dir, "report_%s.txt" % stamp), "w", encoding="utf-8") as f:
        f.write(build_report(results, hr_path, as_of, dry_run=False))
    if credentials:
        path = os.path.join(out_dir, "new_credentials_%s.csv" % stamp)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["username", "temporary_password"])
            w.writerows(credentials)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        log.warning("Temporary passwords were written to %s - hand them over securely, then delete the file", path)


def build_report(results, hr_path, as_of, dry_run):
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = ["EMPLOYEE ACCOUNT AUTOMATION REPORT", "=" * 34,
             "Run date : %s" % as_of, "Mode     : %s" % ("DRY RUN (nothing was changed)" if dry_run else "APPLY"),
             "HR file  : %s" % os.path.basename(hr_path), "", "SUMMARY"]
    for status in ("CREATED", "ENABLED", "UPDATED", "DISABLED", "PURGED", "SKIPPED", "DEFERRED", "PURGE_DUE", "REJECTED"):
        if status in counts:
            lines.append("  %-10s %d" % (status, counts[status]))
    lines += ["", "DETAILS", "  %-5s %-9s %-10s %-9s %-14s %s" % ("line", "employee", "event", "status", "username", "detail")]
    for r in results:
        lines.append("  %-5s %-9s %-10s %-9s %-14s %s" % (r.line or "-", r.employee_id or "-", r.action, r.status, r.username or "-", r.detail))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------ CLI
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Apply HR events (HIRE/TERMINATE/TRANSFER) to a simulated user directory.")
    p.add_argument("--hr", required=True, help="HR events CSV file")
    p.add_argument("--directory", default="data/directory.json", help="user directory JSON file (default: data/directory.json)")
    p.add_argument("--policy", default="data/policy.json", help="department/group policy JSON (default: data/policy.json)")
    p.add_argument("--out-dir", default="output", help="folder for audit log, report and credentials (default: output)")
    p.add_argument("--as-of", help="run date YYYY-MM-DD (default: today); events after this date are deferred")
    p.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    p.add_argument("--purge", action="store_true", help="delete accounts disabled longer than the retention period")
    return p.parse_args(argv)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):                       # Arabic names on Windows consoles
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    try:
        as_of = datetime.strptime(args.as_of, "%Y-%m-%d").date() if args.as_of else date.today()
    except ValueError:
        log.error("--as-of must be YYYY-MM-DD")
        return EXIT_FATAL
    try:
        results, _ = run(args.hr, args.directory, args.policy, args.out_dir, as_of, args.dry_run, args.purge)
    except FatalError as exc:
        log.error("%s", exc)
        return EXIT_FATAL
    except OSError as exc:
        log.error("File system error: %s", exc)
        return EXIT_FATAL

    print()
    print(build_report(results, args.hr, as_of, args.dry_run))
    rejected = sum(1 for r in results if r.status == "REJECTED")
    if rejected:
        log.warning("%d row(s) were rejected - see the report; exit code 1", rejected)
        return EXIT_REJECTED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
