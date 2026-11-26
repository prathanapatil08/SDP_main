import math


RESOURCE_NORMAL_MAX = 91.0
RESOURCE_WARNING_THRESHOLD = 92.0
RESOURCE_CRITICAL_THRESHOLD = 95.0


def resource_severity(value):
    try:
        reading = float(value)
    except (TypeError, ValueError):
        return "Unknown"

    if not math.isfinite(reading):
        return "Unknown"
    if reading >= RESOURCE_CRITICAL_THRESHOLD:
        return "Critical"
    if reading > RESOURCE_NORMAL_MAX:
        return "Warning"
    return "Normal"
