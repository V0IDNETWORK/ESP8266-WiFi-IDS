/**
 * WiFi Security Monitor — main entry point
 *
 * Wires together: FrameSniffer (capture) -> DeauthDetector + RogueAPDetector
 * (analysis) -> AlertLogger (storage) -> WebDashboard (read-only display).
 *
 * This firmware is receive-only. It does not transmit deauth, disassoc, or
 * spoofed beacon frames at any point. See README.md for scope and ethics.
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>

#include "FrameSniffer.h"
#include "DeauthDetector.h"
#include "RogueAPDetector.h"
#include "AlertLogger.h"
#include "WebDashboard.h"

// Detection thresholds — tune these for your lab environment.
static constexpr uint16_t DEAUTH_FRAME_THRESHOLD = 5;    // frames
static constexpr uint32_t DEAUTH_WINDOW_MS       = 1000; // per this many ms
static constexpr uint32_t ROGUE_AP_SCAN_INTERVAL_MS = 15000;

DeauthDetector   deauthDetector(DEAUTH_FRAME_THRESHOLD, DEAUTH_WINDOW_MS);
RogueAPDetector  rogueApDetector(ROGUE_AP_SCAN_INTERVAL_MS);
WebDashboard     dashboard;

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println("\nWiFi Security Monitor booting...");

    // The dashboard needs an IP to be reachable. Easiest lab setup: run the
    // ESP8266 as a soft AP so you can connect a laptop/phone directly to it
    // without depending on external infrastructure while the radio is busy
    // in promiscuous mode.
    WiFi.mode(WIFI_AP);
    WiFi.softAP("WiFi-Security-Monitor", "monitor-lab-only");
    Serial.print("Dashboard AP IP: ");
    Serial.println(WiFi.softAPIP());

    dashboard.begin();

    // Wire the sniffer's parsed frames into both detectors.
    FrameSniffer& sniffer = FrameSniffer::instance();
    sniffer.addListener([](const ParsedFrame& f) { deauthDetector.onFrame(f); });
    sniffer.begin();

    AlertLogger::instance().raise(AlertSeverity::INFO, "main", "Monitor started");
}

void loop() {
    dashboard.handleClient();
    rogueApDetector.update();

    // FrameSniffer delivers frames via an interrupt-driven SDK callback, so
    // there's nothing to poll for it here — DeauthDetector reacts as frames
    // arrive.
}
