#pragma once
#include <Arduino.h>

struct KnownAP {
    String ssid;
    uint8_t bssid[6];
    uint8_t channel;
    bool baselineSet;
};

class RogueAPDetector {
public:
    // scanIntervalMs: how often to run a scan cycle.
    explicit RogueAPDetector(uint32_t scanIntervalMs = 15000);

    // Call from loop(). Internally rate-limited to scanIntervalMs.
    void update();

    // Optionally seed a known-good SSID/BSSID pair ahead of time (e.g. your
    // lab's legitimate AP), so the first scan doesn't have to learn it.
    void addTrustedAP(const String& ssid, const uint8_t* bssid, uint8_t channel);

private:
    static constexpr size_t MAX_KNOWN_APS = 16;
    KnownAP _known[MAX_KNOWN_APS];
    size_t _knownCount = 0;

    uint32_t _scanIntervalMs;
    uint32_t _lastScanMs = 0;

    void runScanCycle();
    KnownAP* findKnown(const String& ssid);
    static bool bssidEquals(const uint8_t* a, const uint8_t* b);
    static String bssidToString(const uint8_t* b);
};
