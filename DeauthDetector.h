#pragma once
/**
 * DeauthDetector
 * --------------
 * Watches parsed 802.11 frames for deauthentication and disassociation
 * traffic and raises an alert when the observed rate, from a given source
 * MAC, exceeds a threshold within a sliding time window.
 *
 * Rationale: on a healthy network, deauth/disassoc frames are rare (a
 * client roaming or powering off). A flood of them in a short window is
 * the classic signature of a deauth attack tool, since attackers typically
 * repeat the forged frame to keep the target disconnected.
 */

#include <Arduino.h>
#include "FrameSniffer.h"
#include "AlertLogger.h"

class DeauthDetector {
public:
    // threshold: number of deauth/disassoc frames from one source MAC
    // within windowMs that triggers an alert.
    DeauthDetector(uint16_t threshold = 5, uint32_t windowMs = 1000);

    // Feed a parsed frame in. Call this from a FrameSniffer listener.
    void onFrame(const ParsedFrame& frame);

private:
    struct SourceActivity {
        uint8_t mac[6];
        uint16_t countInWindow;
        uint32_t windowStartMs;
        bool alertedThisWindow;
        bool inUse;
    };

    static constexpr size_t MAX_TRACKED_SOURCES = 16;
    SourceActivity _sources[MAX_TRACKED_SOURCES];

    uint16_t _threshold;
    uint32_t _windowMs;

    SourceActivity* findOrCreate(const uint8_t* mac);
    static bool macEquals(const uint8_t* a, const uint8_t* b);
    static String macToString(const uint8_t* mac);
};
