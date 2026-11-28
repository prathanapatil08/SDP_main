import getpass
import math
import time

import psutil


_CHROME_PROCESS_NAMES = {
    "chrome.exe",
    "chrome",
    "google chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
}
_PROCESS_ERRORS = (
    psutil.AccessDenied,
    psutil.NoSuchProcess,
    psutil.ZombieProcess,
    OSError,
)


def _short_username(value):
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def sample_chrome_process_metrics(
    process_provider=psutil,
    current_user=None,
    sample_interval=0.25,
    sleep=time.sleep,
    clock=time.perf_counter,
):
    if (
        isinstance(sample_interval, bool)
        or not isinstance(sample_interval, (int, float))
        or not math.isfinite(sample_interval)
        or sample_interval <= 0
    ):
        raise ValueError("The Chrome CPU sample interval must be positive.")

    username = getpass.getuser() if current_user is None else current_user
    username = _short_username(username)
    if not username:
        raise ValueError("The current user could not be identified.")

    processes = []
    skipped = 0
    try:
        process_iterator = process_provider.process_iter(["name", "username"])
        for process in process_iterator:
            try:
                info = process.info
                process_name = str(info.get("name") or "").casefold()
                if process_name not in _CHROME_PROCESS_NAMES:
                    continue
                if _short_username(info.get("username")) != username:
                    continue
                processes.append(
                    (process, process.create_time(), process.cpu_times())
                )
            except _PROCESS_ERRORS:
                skipped += 1
    except _PROCESS_ERRORS as error:
        return {
            "cpu_percent": None,
            "memory_mib": None,
            "memory_percent": None,
            "process_count": 0,
            "error": f"Could not enumerate Chrome processes: {error}",
            "warning": None,
        }

    if not processes:
        return {
            "cpu_percent": None,
            "memory_mib": None,
            "memory_percent": None,
            "process_count": 0,
            "error": (
                "No accessible Chrome processes were found for the current user."
                if skipped
                else "No Chrome processes were found for the current user."
            ),
            "warning": (
                f"Skipped {skipped} inaccessible process(es)."
                if skipped
                else None
            ),
        }

    start_time = clock()
    sleep(sample_interval)
    elapsed = clock() - start_time
    if elapsed <= 0:
        return {
            "cpu_percent": None,
            "memory_mib": None,
            "memory_percent": None,
            "process_count": 0,
            "error": "Could not measure a positive Chrome CPU sample interval.",
            "warning": None,
        }

    cpu_seconds = 0.0
    memory_bytes = 0
    sampled = 0
    for process, create_time, start_cpu in processes:
        try:
            if process.create_time() != create_time:
                skipped += 1
                continue
            end_cpu = process.cpu_times()
            memory = process.memory_info()
            cpu_delta = (
                end_cpu.user
                + end_cpu.system
                - start_cpu.user
                - start_cpu.system
            )
            if cpu_delta < 0:
                skipped += 1
                continue
            cpu_seconds += cpu_delta
            memory_bytes += memory.rss
            sampled += 1
        except _PROCESS_ERRORS:
            skipped += 1

    if not sampled:
        return {
            "cpu_percent": None,
            "memory_mib": None,
            "memory_percent": None,
            "process_count": 0,
            "error": "Chrome processes changed or became inaccessible during sampling.",
            "warning": None,
        }

    try:
        logical_cpu_count = process_provider.cpu_count(logical=True)
        total_memory = process_provider.virtual_memory().total
    except _PROCESS_ERRORS as error:
        return {
            "cpu_percent": None,
            "memory_mib": memory_bytes / (1024 * 1024),
            "memory_percent": None,
            "process_count": sampled,
            "error": f"Could not read host CPU or memory capacity: {error}",
            "warning": (
                f"Skipped {skipped} inaccessible or changing Chrome process(es)."
                if skipped
                else None
            ),
        }
    has_cpu_capacity = (
        isinstance(logical_cpu_count, (int, float))
        and logical_cpu_count > 0
    )
    has_memory_capacity = (
        isinstance(total_memory, (int, float))
        and total_memory > 0
    )
    warning = (
        f"Skipped {skipped} inaccessible or changing Chrome process(es)."
        if skipped
        else None
    )
    return {
        "cpu_percent": (
            100 * cpu_seconds / (elapsed * logical_cpu_count)
            if has_cpu_capacity
            else None
        ),
        "memory_mib": memory_bytes / (1024 * 1024),
        "memory_percent": (
            100 * memory_bytes / total_memory if has_memory_capacity else None
        ),
        "process_count": sampled,
        "error": (
            None
            if has_cpu_capacity and has_memory_capacity
            else "Host CPU or memory capacity could not be read."
        ),
        "warning": warning,
    }
