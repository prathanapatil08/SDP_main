(() => {
  if (globalThis.__sdpPageMetricsStarted) {
    return;
  }
  globalThis.__sdpPageMetricsStarted = true;

  const REPORT_INTERVAL_MS = 30_000;
  let longTaskCount = null;
  let totalLongTaskDurationMs = null;
  let lastReportAt = performance.now();
  let stopped = false;
  let observer = null;

  if (typeof PerformanceObserver === "function") {
    try {
      observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (Number.isFinite(entry.duration) && entry.duration >= 0) {
            longTaskCount += 1;
            totalLongTaskDurationMs += entry.duration;
          }
        }
      });
      observer.observe({ entryTypes: ["longtask"] });
      longTaskCount = 0;
      totalLongTaskDurationMs = 0;
    } catch {
      longTaskCount = null;
      totalLongTaskDurationMs = null;
    }
  }

  function report() {
    if (stopped) {
      return;
    }
    const reportAt = performance.now();
    const reportedTaskCount = longTaskCount;
    const reportedTaskDurationMs = totalLongTaskDurationMs;
    const memory = performance.memory;
    const heapBytes =
      memory &&
      Number.isFinite(memory.usedJSHeapSize) &&
      memory.usedJSHeapSize >= 0
        ? memory.usedJSHeapSize
        : null;
    const payload = {
      origin: location.origin,
      page_url: location.origin,
      hostname: location.hostname,
      timestamp: new Date().toISOString(),
      measurement_interval_seconds: Math.max(
        0.001,
        (reportAt - lastReportAt) / 1000,
      ),
      javascript_heap_used_bytes: heapBytes,
      javascript_heap_available: heapBytes !== null,
      long_task_count: longTaskCount,
      total_long_task_duration_ms: totalLongTaskDurationMs,
      long_tasks_available: longTaskCount !== null,
    };

    chrome.runtime.sendMessage({
      type: "SDP_PAGE_METRICS",
      payload,
    }).then((result) => {
      if (!result?.ok) {
        return;
      }
      if (reportedTaskCount !== null) {
        longTaskCount = Math.max(0, longTaskCount - reportedTaskCount);
        totalLongTaskDurationMs = Math.max(
          0,
          totalLongTaskDurationMs - reportedTaskDurationMs,
        );
      }
      lastReportAt = reportAt;
    }).catch(() => {});
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type !== "SDP_STOP_PAGE_METRICS") {
      return false;
    }
    stopped = true;
    clearInterval(reportTimer);
    observer?.disconnect();
    return false;
  });

  const reportTimer = setInterval(report, REPORT_INTERVAL_MS);
  chrome.runtime.sendMessage({ type: "SDP_PAGE_METRICS_STARTED" }).catch(() => {});
  report();
})();
