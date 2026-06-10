from datetime import datetime

from app.services.schedule_utils import compute_next_daily_run_at, sanitize_daily_time


def test_sanitize_daily_time_normalizes_and_falls_back():
    assert sanitize_daily_time("3:5") == "03:05"
    assert sanitize_daily_time("23:59") == "23:59"
    assert sanitize_daily_time("25:00") == "02:00"
    assert sanitize_daily_time("bad-value") == "02:00"


def test_compute_next_daily_run_at_rolls_to_next_day_when_needed():
    reference = datetime(2026, 5, 11, 5, 30, 0)

    same_day = compute_next_daily_run_at("06:00", reference_utc=reference)
    next_day = compute_next_daily_run_at("02:00", reference_utc=reference)

    assert same_day > reference
    assert next_day > same_day
