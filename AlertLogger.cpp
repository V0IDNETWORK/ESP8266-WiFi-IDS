#include "AlertLogger.h"

AlertLogger& AlertLogger::instance() {
    static AlertLogger logger;
    return logger;
}

const char* AlertLogger::severityLabel(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::INFO:     return "INFO";
        case AlertSeverity::WARNING:  return "WARNING";
        case AlertSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

void AlertLogger::raise(AlertSeverity severity, const String& source, const String& message) {
    Alert a;
    a.timestampMs = millis();
    a.severity = severity;
    a.source = source;
    a.message = message;

    _buffer[_writeIndex] = a;
    _writeIndex = (_writeIndex + 1) % CAPACITY;
    if (_storedCount < CAPACITY) _storedCount++;

    Serial.printf("[%lu] %s (%s): %s\n",
                  static_cast<unsigned long>(a.timestampMs),
                  severityLabel(a.severity),
                  a.source.c_str(),
                  a.message.c_str());
}

size_t AlertLogger::count() const {
    return _storedCount;
}

const Alert& AlertLogger::get(size_t i) const {
    // Logical index 0 = oldest stored alert.
    size_t start = (_storedCount < CAPACITY) ? 0 : _writeIndex;
    size_t physicalIndex = (start + i) % CAPACITY;
    return _buffer[physicalIndex];
}
