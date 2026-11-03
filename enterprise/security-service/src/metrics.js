const STATUSES = ["open", "acknowledged", "resolved"];
const SEVERITIES = ["warning", "high", "critical"];

function label(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function sample(name, value, labels = {}) {
  const entries = Object.entries(labels);
  const suffix = entries.length
    ? `{${entries.map(([key, item]) => `${key}="${label(item)}"`).join(",")}}`
    : "";
  return `${name}${suffix} ${value}`;
}

export function renderPrometheusMetrics(snapshot) {
  const lines = [
    "# HELP magpie_security_detection_events_total Accepted detection events.",
    "# TYPE magpie_security_detection_events_total counter",
    sample("magpie_security_detection_events_total", snapshot.acceptedEvents),
    "# HELP magpie_security_detection_events_duplicate_total Replayed detection events.",
    "# TYPE magpie_security_detection_events_duplicate_total counter",
    sample("magpie_security_detection_events_duplicate_total", snapshot.duplicateEvents),
    "# HELP magpie_security_findings_total Findings produced by the rule engine.",
    "# TYPE magpie_security_findings_total counter",
    sample("magpie_security_findings_total", snapshot.findings),
    "# HELP magpie_security_findings_suppressed_total Findings retained while suppressed.",
    "# TYPE magpie_security_findings_suppressed_total counter",
    sample("magpie_security_findings_suppressed_total", snapshot.suppressedFindings),
    "# HELP magpie_security_alerts Current alerts by lifecycle state.",
    "# TYPE magpie_security_alerts gauge",
  ];
  for (const status of STATUSES) {
    lines.push(sample("magpie_security_alerts", snapshot.alerts.byStatus[status] || 0, {
      status,
    }));
  }
  lines.push(
    "# HELP magpie_security_alerts_by_severity Current alerts by severity.",
    "# TYPE magpie_security_alerts_by_severity gauge",
  );
  for (const severity of SEVERITIES) {
    lines.push(sample(
      "magpie_security_alerts_by_severity",
      snapshot.alerts.bySeverity[severity] || 0,
      { severity },
    ));
  }
  lines.push(
    "# HELP magpie_security_alerts_unassigned Active alerts without an owner.",
    "# TYPE magpie_security_alerts_unassigned gauge",
    "# HELP magpie_security_alerts_overdue Active alerts past their response SLA.",
    "# TYPE magpie_security_alerts_overdue gauge",
    "# HELP magpie_security_alert_oldest_age_seconds Age of the oldest active alert.",
    "# TYPE magpie_security_alert_oldest_age_seconds gauge",
  );
  for (const severity of SEVERITIES) {
    lines.push(sample(
      "magpie_security_alerts_unassigned",
      snapshot.alerts.unassigned[severity] || 0,
      { severity },
    ));
    lines.push(sample(
      "magpie_security_alerts_overdue",
      snapshot.alerts.overdue[severity] || 0,
      { severity },
    ));
    lines.push(sample(
      "magpie_security_alert_oldest_age_seconds",
      snapshot.alerts.oldest[severity] || 0,
      { severity },
    ));
  }
  lines.push(
    "# HELP magpie_security_response_actions Current response actions by state.",
    "# TYPE magpie_security_response_actions gauge",
  );
  for (const status of [
    "requested",
    "approved",
    "active",
    "reverted",
    "expired",
    "failed",
  ]) {
    lines.push(sample(
      "magpie_security_response_actions",
      snapshot.responseActions[status] || 0,
      { status },
    ));
  }
  lines.push(
    "# HELP magpie_security_store_records Current records retained by the security store.",
    "# TYPE magpie_security_store_records gauge",
  );
  for (const kind of ["events", "findings", "alerts", "responseActions"]) {
    lines.push(sample("magpie_security_store_records", snapshot.store[kind] || 0, { kind }));
  }
  return `${lines.join("\n")}\n`;
}
