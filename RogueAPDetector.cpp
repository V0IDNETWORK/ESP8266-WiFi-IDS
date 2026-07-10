#include "RogueAPDetector.h"
#include <ESP8266WiFi.h>
#include "AlertLogger.h"

RogueAPDetector::RogueAPDetector(uint32_t scanIntervalMs)
    : _scanIntervalMs(scanIntervalMs) {}

bool RogueAPDetector::bssidEquals(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

String RogueAPDetector::bssidToString(const uint8_t* b) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
              b[0], b[1], b[2], b[3], b[4], b[5]);
    return String(buf);
}

void RogueAPDetector::addTrustedAP(const String& ssid, const uint8_t* bssid, uint8_t channel) {
    if (_knownCount >= MAX_KNOWN_APS) return;
    KnownAP& k = _known[_knownCount++];
    k.ssid = ssid;
    memcpy(k.bssid, bssid, 6);
    k.channel = channel;
    k.baselineSet = true;
}

KnownAP* RogueAPDetector::findKnown(const String& ssid) {
    for (size_t i = 0; i < _knownCount; i++) {
        if (_known[i].ssid == ssid) return &_known[i];
    }
    return nullptr;
}

void RogueAPDetector::update() {
    uint32_t now = millis();
    if (now - _lastScanMs < _scanIntervalMs) return;
    _lastScanMs = now;
    runScanCycle();
}

void RogueAPDetector::runScanCycle() {
    int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
    if (n < 0) return; // scan failed or in progress

    for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) continue; // skip hidden/blank SSIDs

        const uint8_t* bssid = WiFi.BSSID(i);
        uint8_t channel = WiFi.channel(i);

        KnownAP* known = findKnown(ssid);

        if (known == nullptr) {
            // First time we've seen this SSID — record it as this run's
            // baseline. (For stronger guarantees, seed addTrustedAP()
            // ahead of time with your lab's real AP details instead of
            // learning on the fly.)
            if (_knownCount < MAX_KNOWN_APS) {
                KnownAP& k = _known[_knownCount++];
                k.ssid = ssid;
                memcpy(k.bssid, bssid, 6);
                k.channel = channel;
                k.baselineSet = true;
            }
            continue;
        }

        bool bssidChanged = !bssidEquals(known->bssid, bssid);
        bool channelChanged = (known->channel != channel);

        if (bssidChanged) {
            String message = "SSID \"" + ssid + "\" seen on unexpected BSSID " +
                              bssidToString(bssid) + " (baseline was " +
                              bssidToString(known->bssid) +
                              ") — possible rogue/evil-twin AP";
            AlertLogger::instance().raise(AlertSeverity::WARNING, "RogueAPDetector", message);
        } else if (channelChanged) {
            String message = "SSID \"" + ssid + "\" changed channel " +
                              String(known->channel) + " -> " + String(channel) +
                              " — verify this is expected";
            AlertLogger::instance().raise(AlertSeverity::INFO, "RogueAPDetector", message);
            known->channel = channel;
        }
    }
}
