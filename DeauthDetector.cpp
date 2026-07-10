#include "DeauthDetector.h"

DeauthDetector::DeauthDetector(uint16_t threshold, uint32_t windowMs)
    : _threshold(threshold), _windowMs(windowMs) {
    for (auto& s : _sources) s.inUse = false;
}

bool DeauthDetector::macEquals(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

String DeauthDetector::macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

DeauthDetector::SourceActivity* DeauthDetector::findOrCreate(const uint8_t* mac) {
    SourceActivity* freeSlot = nullptr;

    for (auto& s : _sources) {
        if (s.inUse && macEquals(s.mac, mac)) return &s;
        if (!s.inUse && freeSlot == nullptr) freeSlot = &s;
    }

    if (freeSlot != nullptr) {
        memcpy(freeSlot->mac, mac, 6);
        freeSlot->countInWindow = 0;
        freeSlot->windowStartMs = millis();
        freeSlot->alertedThisWindow = false;
        freeSlot->inUse = true;
        return freeSlot;
    }

    // Table full — evict the oldest-window entry to make room. In a
    // real deployment you'd size MAX_TRACKED_SOURCES to your environment
    // or back this with a hash map; a fixed table keeps the MCU-friendly
    // memory footprint predictable for this teaching example.
    SourceActivity* oldest = &_sources[0];
    for (auto& s : _sources) {
        if (s.windowStartMs < oldest->windowStartMs) oldest = &s;
    }
    memcpy(oldest->mac, mac, 6);
    oldest->countInWindow = 0;
    oldest->windowStartMs = millis();
    oldest->alertedThisWindow = false;
    oldest->inUse = true;
    return oldest;
}

void DeauthDetector::onFrame(const ParsedFrame& frame) {
    if (frame.frameSubtype != Dot11::SUBTYPE_DEAUTH &&
        frame.frameSubtype != Dot11::SUBTYPE_DISASSOC) {
        return;
    }

    SourceActivity* activity = findOrCreate(frame.srcMac);
    uint32_t now = millis();

    if (now - activity->windowStartMs > _windowMs) {
        // Window expired — start a new one.
        activity->windowStartMs = now;
        activity->countInWindow = 0;
        activity->alertedThisWindow = false;
    }

    activity->countInWindow++;

    if (activity->countInWindow >= _threshold && !activity->alertedThisWindow) {
        activity->alertedThisWindow = true;

        const char* frameType = (frame.frameSubtype == Dot11::SUBTYPE_DEAUTH)
                                     ? "deauth" : "disassoc";

        String message = String("Possible ") + frameType + " flood from " +
                          macToString(frame.srcMac) + " targeting " +
                          macToString(frame.destMac) + " (" +
                          String(activity->countInWindow) + " frames in " +
                          String(_windowMs) + "ms, ch " + String(frame.channel) +
                          ", rssi " + String(frame.rssi) + "dBm)";

        AlertLogger::instance().raise(AlertSeverity::CRITICAL, "DeauthDetector", message);
    }
}
