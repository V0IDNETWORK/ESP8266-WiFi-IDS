#pragma once
/**
 * AlertLogger
 * -----------
 * A small fixed-size ring buffer of timestamped security alerts, shared
 * between the detector modules (producers) and the WebDashboard (consumer).
 */

#include <Arduino.h>

enum class AlertSeverity : uint8_t {
    INFO,
    WARNING,
    CRITICAL
};

struct Alert {
    uint32_t timestampMs;
    AlertSeverity severity;
    String source;   // which detector raised it, e.g. "DeauthDetector"
    String message;  // human-readable description
};

class AlertLogger {
public:
    static constexpr size_t CAPACITY = 32;

    // Records a new alert, printing it to Serial and storing it in the
    // ring buffer (oldest entries are overwritten once full).
    void raise(AlertSeverity severity, const String& source, const String& message);

    // Returns the number of alerts currently stored (<= CAPACITY).
    size_t count() const;

    // Returns the alert at logical index i, where 0 is the oldest
    // currently-stored alert and count()-1 is the most recent.
    const Alert& get(size_t i) const;

    static AlertLogger& instance();

private:
    Alert _buffer[CAPACITY];
    size_t _writeIndex = 0;
    size_t _storedCount = 0;

    static const char* severityLabel(AlertSeverity s);
};
