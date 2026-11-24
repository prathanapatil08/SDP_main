import math
from datetime import datetime


TREND_POLICIES = (
    ("cpu_usage", "CPU utilization", 85.0, "%"),
    ("memory_usage", "Memory utilization", 90.0, "%"),
    ("disk_usage", "Disk utilization", 90.0, "%"),
    ("response_time_ms", "API response time", 1000.0, " ms"),
    ("api_error_rate", "API error rate", 5.0, "%"),
)
HISTORY_WINDOW_MINUTES = 30
FORECAST_HORIZON_MINUTES = 30
MIN_TREND_SAMPLES = 6
MIN_TREND_SPAN_SECONDS = 60
MIN_RISING_FRACTION = 0.6


def _timestamp_seconds(value):
    try:
        timestamp = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).strip())
        )
    except (TypeError, ValueError):
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.astimezone()
    return timestamp.timestamp()


def forecast_threshold_crossings(readings):
    samples_by_metric = {column: {} for column, _, _, _ in TREND_POLICIES}
    for reading in readings:
        timestamp = _timestamp_seconds(reading.get("timestamp"))
        if timestamp is None:
            continue
        for column, _, _, _ in TREND_POLICIES:
            try:
                value = float(reading.get(column))
            except (TypeError, ValueError):
                continue
            if math.isfinite(value):
                samples_by_metric[column][timestamp] = value

    warnings = []
    eligible_metrics = []
    insufficient_metrics = []
    for column, label, threshold, unit in TREND_POLICIES:
        samples = sorted(samples_by_metric[column].items())
        if not samples:
            insufficient_metrics.append(label)
            continue

        latest_time = samples[-1][0]
        window_start = latest_time - HISTORY_WINDOW_MINUTES * 60
        samples = [
            (timestamp, value)
            for timestamp, value in samples
            if timestamp >= window_start
        ]
        span_seconds = samples[-1][0] - samples[0][0]
        if (
            len(samples) < MIN_TREND_SAMPLES
            or span_seconds < MIN_TREND_SPAN_SECONDS
        ):
            insufficient_metrics.append(label)
            continue

        eligible_metrics.append(label)
        current_value = samples[-1][1]
        if current_value >= threshold:
            continue

        elapsed_minutes = [
            (timestamp - samples[0][0]) / 60
            for timestamp, _ in samples
        ]
        values = [value for _, value in samples]
        mean_time = math.fsum(elapsed_minutes) / len(elapsed_minutes)
        mean_value = math.fsum(values) / len(values)
        time_variance = math.fsum(
            (elapsed - mean_time) ** 2 for elapsed in elapsed_minutes
        )
        if time_variance == 0:
            continue
        slope_per_minute = math.fsum(
            (elapsed - mean_time) * (value - mean_value)
            for elapsed, value in zip(elapsed_minutes, values)
        ) / time_variance
        rising_steps = sum(
            later > earlier for earlier, later in zip(values, values[1:])
        )
        rising_fraction = rising_steps / (len(values) - 1)
        if (
            slope_per_minute <= 0
            or values[-1] <= values[0]
            or rising_fraction < MIN_RISING_FRACTION
        ):
            continue

        minutes_to_threshold = (threshold - current_value) / slope_per_minute
        if 0 < minutes_to_threshold <= FORECAST_HORIZON_MINUTES:
            warnings.append(
                {
                    "metric": column,
                    "label": label,
                    "current_value": current_value,
                    "threshold": threshold,
                    "unit": unit,
                    "slope_per_hour": slope_per_minute * 60,
                    "minutes_to_threshold": minutes_to_threshold,
                    "samples": len(samples),
                }
            )

    warnings.sort(key=lambda warning: warning["minutes_to_threshold"])
    return {
        "warnings": warnings,
        "eligible_metrics": eligible_metrics,
        "insufficient_metrics": insufficient_metrics,
    }
