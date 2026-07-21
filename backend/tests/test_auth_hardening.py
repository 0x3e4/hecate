"""Tests for constant-time secret comparison and the auth throttle/lockout."""
from __future__ import annotations

from app.core.auth_throttle import AuthThrottle
from app.core.passwords import secret_equals


# --------------------------------------------------------------------------
# secret_equals — constant-time shared-secret comparison
# --------------------------------------------------------------------------

def test_secret_equals_matches_identical():
    assert secret_equals("hunter2", "hunter2") is True


def test_secret_equals_rejects_different():
    assert secret_equals("hunter2", "hunter3") is False
    assert secret_equals("short", "a-much-longer-secret") is False


def test_secret_equals_rejects_missing_sides():
    # An unset expected secret must never match (fail-closed), and a None
    # provided value must not blow up.
    assert secret_equals("anything", None) is False
    assert secret_equals("anything", "") is False
    assert secret_equals(None, "expected") is False


def test_secret_equals_handles_non_ascii():
    assert secret_equals("pä$$wörd", "pä$$wörd") is True
    assert secret_equals("pä$$wörd", "passwoord") is False


# --------------------------------------------------------------------------
# AuthThrottle — sliding-window failure counter + lockout
# --------------------------------------------------------------------------

def _with_clock(monkeypatch, start=1000.0):
    clock = {"t": start}
    monkeypatch.setattr(AuthThrottle, "_now", staticmethod(lambda: clock["t"]))
    return clock


def test_locks_out_after_max_attempts(monkeypatch):
    _with_clock(monkeypatch)
    t = AuthThrottle(max_attempts=3, window_seconds=60, lockout_seconds=300)

    assert t.remaining_lockout("k") is None
    t.record_failure("k")
    t.record_failure("k")
    assert t.remaining_lockout("k") is None      # under the threshold
    t.record_failure("k")                          # third failure trips the lock
    remaining = t.remaining_lockout("k")
    assert remaining is not None and 0 < remaining <= 300


def test_lockout_expires_after_window(monkeypatch):
    clock = _with_clock(monkeypatch)
    t = AuthThrottle(max_attempts=2, window_seconds=60, lockout_seconds=300)
    t.record_failure("k")
    t.record_failure("k")
    assert t.remaining_lockout("k") is not None
    clock["t"] += 301
    assert t.remaining_lockout("k") is None       # lock cleared, fresh window


def test_success_clears_failures(monkeypatch):
    _with_clock(monkeypatch)
    t = AuthThrottle(max_attempts=3, window_seconds=60, lockout_seconds=300)
    t.record_failure("k")
    t.record_failure("k")
    t.record_success("k")
    # Counter reset — two more failures must NOT lock (would need 3 fresh ones).
    t.record_failure("k")
    t.record_failure("k")
    assert t.remaining_lockout("k") is None


def test_old_failures_slide_out_of_window(monkeypatch):
    clock = _with_clock(monkeypatch)
    t = AuthThrottle(max_attempts=3, window_seconds=60, lockout_seconds=300)
    t.record_failure("k")
    t.record_failure("k")
    clock["t"] += 61                               # first two age out of the window
    t.record_failure("k")
    t.record_failure("k")
    assert t.remaining_lockout("k") is None        # only 2 fresh failures


def test_keys_are_isolated(monkeypatch):
    _with_clock(monkeypatch)
    t = AuthThrottle(max_attempts=2, window_seconds=60, lockout_seconds=300)
    t.record_failure("a")
    t.record_failure("a")
    assert t.remaining_lockout("a") is not None
    assert t.remaining_lockout("b") is None        # different client unaffected
