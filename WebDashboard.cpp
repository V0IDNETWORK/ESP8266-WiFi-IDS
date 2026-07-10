#include "WebDashboard.h"
#include "AlertLogger.h"

void WebDashboard::begin() {
    _server.on("/", HTTP_GET, [this]() { handleRoot(); });
    _server.on("/alerts.json", HTTP_GET, [this]() { handleAlertsJson(); });
    _server.begin();
}

void WebDashboard::handleClient() {
    _server.handleClient();
}

static const char* severityToLabel(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::INFO:     return "INFO";
        case AlertSeverity::WARNING:  return "WARNING";
        case AlertSeverity::CRITICAL: return "CRITICAL";
    }
    return "?";
}

static const char* severityToColor(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::INFO:     return "#2e7d32"; // green
        case AlertSeverity::WARNING:  return "#f9a825"; // amber
        case AlertSeverity::CRITICAL: return "#c62828"; // red
    }
    return "#666";
}

String WebDashboard::renderPage() const {
    AlertLogger& log = AlertLogger::instance();

    String html;
    html.reserve(2048);
    html += "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    html += "<title>WiFi Security Monitor</title>";
    html += "<meta http-equiv='refresh' content='5'>"; // simple auto-refresh, no JS required
    html += "<style>";
    html += "body{font-family:sans-serif;background:#f5f5f5;color:#222;margin:0;padding:20px;}";
    html += "h1{font-size:20px;} table{width:100%;border-collapse:collapse;background:#fff;}";
    html += "td,th{padding:8px;border-bottom:1px solid #eee;text-align:left;font-size:14px;}";
    html += ".sev{color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;}";
    html += "</style></head><body>";
    html += "<h1>WiFi Security Monitor — read-only status</h1>";
    html += "<p>Passive 802.11 monitoring. No login, no data entry on this page.</p>";
    html += "<table><tr><th>Time (ms)</th><th>Severity</th><th>Source</th><th>Message</th></tr>";

    size_t total = log.count();
    for (size_t i = total; i > 0; i--) {
        const Alert& a = log.get(i - 1); // newest first
        html += "<tr><td>" + String(a.timestampMs) + "</td><td><span class='sev' style='background:";
        html += severityToColor(a.severity);
        html += "'>";
        html += severityToLabel(a.severity);
        html += "</span></td><td>" + a.source + "</td><td>" + a.message + "</td></tr>";
    }

    if (total == 0) {
        html += "<tr><td colspan='4'>No alerts recorded yet.</td></tr>";
    }

    html += "</table></body></html>";
    return html;
}

void WebDashboard::handleRoot() {
    _server.send(200, "text/html", renderPage());
}

void WebDashboard::handleAlertsJson() {
    AlertLogger& log = AlertLogger::instance();
    String json = "[";
    size_t total = log.count();
    for (size_t i = 0; i < total; i++) {
        const Alert& a = log.get(i);
        if (i > 0) json += ",";
        json += "{\"t\":" + String(a.timestampMs) +
                ",\"severity\":\"" + String(severityToLabel(a.severity)) + "\"" +
                ",\"source\":\"" + a.source + "\"" +
                ",\"message\":\"" + a.message + "\"}";
    }
    json += "]";
    _server.send(200, "application/json", json);
}
