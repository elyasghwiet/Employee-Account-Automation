import csv
import json
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import account_automation as aa  # noqa: E402

POLICY = {
    "retention_days": 30,
    "default_groups": ["all-staff"],
    "departments": {"IT": ["it-staff"], "HR": ["hr-users"], "Finance": ["finance-users"]},
}
HEADER = ["employee_id", "full_name", "department", "event", "effective_date", "latin_name"]
D1 = date(2026, 11, 1)


@pytest.fixture
def env(tmp_path):
    """A temporary folder with a policy file and helpers to write HR files."""
    (tmp_path / "policy.json").write_text(json.dumps(POLICY), encoding="utf-8")

    class Env:
        root = tmp_path
        policy = str(tmp_path / "policy.json")
        directory = str(tmp_path / "directory.json")
        out = str(tmp_path / "out")

        def hr(self, rows, name="hr.csv"):
            path = tmp_path / name
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(HEADER)
                for r in rows:
                    w.writerow(list(r) + [""] * (len(HEADER) - len(r)))
            return str(path)

        def run(self, rows, as_of=D1, **kw):
            return aa.run(self.hr(rows), self.directory, self.policy, self.out, as_of, **kw)

        def users(self):
            with open(self.directory, encoding="utf-8") as f:
                return json.load(f)["users"]

    return Env()


def statuses(results):
    return [r.status for r in results]


# ---- usernames -------------------------------------------------------------
def test_base_username_first_initial_plus_last_name():
    assert aa.base_username("Elyas Ghwiet") == "eghwiet"


def test_username_removes_hyphens_apostrophes_and_accents():
    assert aa.base_username("Sara Al-Harbi") == "salharbi"
    assert aa.base_username("Sean O'Brien") == "sobrien"
    assert aa.base_username("José Núñez") == "jnunez"


def test_username_from_arabic_name_is_ascii():
    name = aa.base_username("محمد الحربي")
    assert name.isascii() and name.isalnum() and len(name) > 2


def test_single_word_name_and_length_limit():
    assert aa.base_username("Madonna") == "madonna"
    assert len(aa.base_username("Alexander Montgomery-Featherstonehaugh")) == 20


def test_name_without_letters_is_rejected():
    with pytest.raises(aa.RowError):
        aa.base_username("123 !!!")


def test_collisions_get_a_number():
    assert aa.unique_username("ahassan", {"ahassan"}) == "ahassan2"
    assert aa.unique_username("ahassan", {"ahassan", "ahassan2"}) == "ahassan3"
    assert aa.unique_username("zed", {"ahassan"}) == "zed"


def test_collision_suffix_respects_max_length():
    base = "a" * 20
    assert len(aa.unique_username(base, {base})) <= 20


# ---- passwords -------------------------------------------------------------
def test_temp_password_is_strong_and_random():
    pws = {aa.new_temp_password() for _ in range(20)}
    assert len(pws) == 20
    for pw in pws:
        assert len(pw) == 14
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)


def test_password_is_stored_only_as_a_hash(env):
    _, creds = env.run([("E1001", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    pw = creds[0][1]
    raw = open(env.directory, encoding="utf-8").read()
    assert pw not in raw and "pbkdf2_sha256" in raw


# ---- hire ------------------------------------------------------------------
def test_hire_creates_account_with_department_groups(env):
    results, creds = env.run([("E1001", "Elyas Ghwiet", "it", "hire", "2026-11-01")])
    assert statuses(results) == ["CREATED"]
    u = env.users()["eghwiet"]
    assert u["status"] == "active" and u["department"] == "IT"
    assert u["groups"] == ["all-staff", "it-staff"] and u["must_change_password"] is True
    assert len(creds) == 1


def test_latin_name_takes_precedence_over_arabic_name(env):
    env.run([("E1003", "محمد الحربي", "Finance", "HIRE", "2026-11-01", "Mohammed Alharbi")])
    assert "malharbi" in env.users()


def test_two_people_with_same_username_base(env):
    env.run([("E101", "Ali Hassan", "IT", "HIRE", "2026-11-01"), ("E102", "Ahmed Hassan", "IT", "HIRE", "2026-11-01")])
    assert {"ahassan", "ahassan2"} <= set(env.users())


def test_future_hire_is_deferred_then_applied_later(env):
    rows = [("E101", "Layla Ibrahim", "HR", "HIRE", "2026-11-20")]
    results, _ = env.run(rows, as_of=date(2026, 11, 1))
    assert statuses(results) == ["DEFERRED"] and env.users() == {}
    results, _ = env.run(rows, as_of=date(2026, 11, 20))
    assert statuses(results) == ["CREATED"] and "librahim" in env.users()


# ---- idempotency -----------------------------------------------------------
def test_running_same_file_twice_changes_nothing(env):
    rows = [("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01"), ("E102", "Sara Harbi", "HR", "HIRE", "2026-11-01")]
    env.run(rows)
    before = open(env.directory, encoding="utf-8").read()
    results, creds = env.run(rows)
    assert statuses(results) == ["SKIPPED", "SKIPPED"] and creds == []
    assert open(env.directory, encoding="utf-8").read() == before


# ---- terminate / transfer / rehire ----------------------------------------------
def test_terminate_disables_and_removes_access(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-12")], as_of=date(2026, 11, 15))
    u = env.users()["eghwiet"]
    assert statuses(results) == ["DISABLED"]
    assert u["status"] == "disabled" and u["groups"] == [] and u["password_hash"] is None
    assert u["disabled_on"] == "2026-11-12"


def test_terminate_unknown_employee_is_rejected(env):
    results, _ = env.run([("E404", "Nobody Here", "IT", "TERMINATE", "2026-11-01")])
    assert statuses(results) == ["REJECTED"] and "no account" in results[0].detail


def test_terminate_twice_is_skipped(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    row = ("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")
    env.run([row], as_of=date(2026, 11, 5))
    results, _ = env.run([row], as_of=date(2026, 11, 5))
    assert statuses(results) == ["SKIPPED"]


def test_transfer_changes_groups(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    results, _ = env.run([("E101", "Elyas Ghwiet", "Finance", "TRANSFER", "2026-11-05")], as_of=date(2026, 11, 6))
    assert statuses(results) == ["UPDATED"]
    assert env.users()["eghwiet"]["groups"] == ["all-staff", "finance-users"]


def test_transfer_of_disabled_account_is_rejected(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=date(2026, 11, 5))
    results, _ = env.run([("E101", "Elyas Ghwiet", "HR", "TRANSFER", "2026-11-03")], as_of=date(2026, 11, 6))
    assert statuses(results) == ["REJECTED"]


def test_rehire_reenables_same_username(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=date(2026, 11, 5))
    results, creds = env.run([("E101", "Elyas Ghwiet", "HR", "HIRE", "2026-11-10")], as_of=date(2026, 11, 10))
    u = env.users()["eghwiet"]
    assert statuses(results) == ["ENABLED"] and u["status"] == "active" and u["department"] == "HR"
    assert len(creds) == 1


def test_events_in_one_file_apply_in_date_order(env):
    rows = [("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-05"), ("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")]
    results, _ = env.run(rows, as_of=date(2026, 11, 6))
    assert sorted(statuses(results)) == ["CREATED", "DISABLED"]


# ---- purge -----------------------------------------------------------------
def test_purge_due_is_reported_and_purge_deletes(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=date(2026, 11, 5))
    late = date(2026, 12, 20)
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=late)
    assert "PURGE_DUE" in statuses(results) and "eghwiet" in env.users()
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=late, purge=True)
    assert "PURGED" in statuses(results) and "eghwiet" not in env.users()


def test_recently_disabled_account_is_not_purge_due(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "TERMINATE", "2026-11-02")], as_of=date(2026, 11, 20), purge=True)
    assert "PURGED" not in statuses(results) and "eghwiet" in env.users()


# ---- validation: bad rows are rejected, good rows still processed -----------------
@pytest.mark.parametrize("row,fragment", [
    (("E102", "Huda Ali", "Legal", "HIRE", "2026-11-01"), "unknown department"),
    (("E103", "Khalid Nasser", "IT", "HIRE", "01/11/2026"), "YYYY-MM-DD"),
    (("E104", "", "IT", "HIRE", "2026-11-01"), "full_name"),
    (("E105", "Mona Said", "IT", "PROMOTE", "2026-11-01"), "unknown event"),
    (("E", "Zed Abc", "IT", "HIRE", "2026-11-01"), "employee_id"),
    (("E107", "Mona Said", "IT", "HIRE", "2026-02-30"), "YYYY-MM-DD"),
])
def test_invalid_rows_are_rejected_but_run_continues(env, row, fragment):
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01"), row])
    by_status = {r.status: r for r in results}
    assert "CREATED" in by_status and "REJECTED" in by_status
    assert fragment in by_status["REJECTED"].detail
    assert list(env.users()) == ["eghwiet"]


# ---- dry run ---------------------------------------------------------------
def test_dry_run_changes_nothing(env):
    results, _ = env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")], dry_run=True)
    assert statuses(results) == ["CREATED"]
    assert not os.path.exists(env.directory) and not os.path.exists(env.out)


# ---- audit & outputs -----------------------------------------------------------
def test_audit_log_report_and_credentials_are_written(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    files = os.listdir(env.out)
    assert "audit.log" in files
    assert any(f.startswith("report_") for f in files) and any(f.startswith("new_credentials_") for f in files)
    assert "CREATED" in open(os.path.join(env.out, "audit.log"), encoding="utf-8").read()


def test_second_run_on_same_day_does_not_overwrite_credentials(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    import time
    time.sleep(1.1)
    env.run([("E102", "Sara Harbi", "HR", "HIRE", "2026-11-01")])
    assert len([f for f in os.listdir(env.out) if f.startswith("new_credentials_")]) == 2


# ---- file-level errors -----------------------------------------------------------
def test_missing_hr_file_is_fatal(env):
    with pytest.raises(aa.FatalError):
        aa.run(str(env.root / "none.csv"), env.directory, env.policy, env.out, D1)


def test_missing_column_is_fatal(env):
    p = env.root / "bad.csv"
    p.write_text("employee_id,full_name\nE1,Aaa\n", encoding="utf-8")
    with pytest.raises(aa.FatalError, match="missing required column"):
        aa.run(str(p), env.directory, env.policy, env.out, D1)


def test_corrupt_directory_is_fatal_and_not_overwritten(env):
    (env.root / "directory.json").write_text('{"broken', encoding="utf-8")
    with pytest.raises(aa.FatalError, match="corrupt"):
        env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    assert (env.root / "directory.json").read_text(encoding="utf-8") == '{"broken'


def test_bad_policy_is_fatal(env):
    (env.root / "policy.json").write_text("{}", encoding="utf-8")
    with pytest.raises(aa.FatalError):
        env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])


def test_excel_bom_and_blank_lines_are_handled(env):
    p = env.root / "excel.csv"
    p.write_bytes(b"\xef\xbb\xbfemployee_id,full_name,department,event,effective_date\r\n\r\nE100,Elyas Ghwiet,IT,HIRE,2026-11-01\r\n")
    results, _ = aa.run(str(p), env.directory, env.policy, env.out, D1)
    assert statuses(results) == ["CREATED"]


def test_backup_of_previous_directory_is_kept(env):
    env.run([("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")])
    env.run([("E102", "Sara Harbi", "HR", "HIRE", "2026-11-01")])
    assert os.path.exists(env.directory + ".bak")
    assert "eghwiet" in json.load(open(env.directory + ".bak", encoding="utf-8"))["users"]


# ---- command line / exit codes ------------------------------------------------------
def cli(env, rows, *extra):
    return aa.main(["--hr", env.hr(rows), "--directory", env.directory, "--policy", env.policy,
                    "--out-dir", env.out, "--as-of", "2026-11-01", *extra])


def test_exit_code_0_when_all_rows_ok(env):
    assert cli(env, [("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")]) == aa.EXIT_OK


def test_exit_code_1_when_a_row_is_rejected(env):
    assert cli(env, [("E101", "Elyas Ghwiet", "Legal", "HIRE", "2026-11-01")]) == aa.EXIT_REJECTED


def test_exit_code_2_on_fatal_error(env):
    assert aa.main(["--hr", str(env.root / "none.csv"), "--policy", env.policy]) == aa.EXIT_FATAL
    assert cli(env, [("E101", "Elyas Ghwiet", "IT", "HIRE", "2026-11-01")], "--as-of", "yesterday") == aa.EXIT_FATAL
