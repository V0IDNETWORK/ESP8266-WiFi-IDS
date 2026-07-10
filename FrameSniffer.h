#pragma once
/**
 * FrameSniffer
 * ------------
 * Puts the ESP8266 radio into promiscuous (monitor) mode and parses raw
 * 802.11 management frames into a structured, easy-to-consume format.
 *
 * RECEIVE-ONLY: this module never calls any packet-transmit SDK function.
 * Its only job is to observe and parse traffic already present in the air.
 */

#include <Arduino.h>
#include <functional>

// 802.11 frame type/subtype byte values we care about (frame control byte 0).
// See IEEE 802.11-2020 clause 9.2.4.1.3 for the full table.
namespace Dot11 {
    constexpr uint8_t TYPE_MASK           = 0xFC; // mask off protocol version bits
    constexpr uint8_t SUBTYPE_BEACON      = 0x80;
    constexpr uint8_t SUBTYPE_PROBE_REQ   = 0x40;
    constexpr uint8_t SUBTYPE_PROBE_RESP  = 0x50;
    constexpr uint8_t SUBTYPE_DEAUTH      = 0xC0;
    constexpr uint8_t SUBTYPE_DISASSOC    = 0xA0;
}

// A parsed, human-usable view of one captured management frame.
struct ParsedFrame {
    uint8_t  frameSubtype;   // one of the Dot11::SUBTYPE_* constants
    uint8_t  destMac[6];     // address 1
    uint8_t  srcMac[6];      // address 2 (transmitter)
    uint8_t  bssid[6];       // address 3
    uint16_t seqNum;         // sequence control field, sequence number portion
    int8_t   rssi;           // signal strength in dBm
    uint8_t  channel;        // capture channel
    uint32_t timestampMs;    // millis() at capture time
};

// Callback signature invoked for every successfully parsed frame.
using FrameListener = std::function<void(const ParsedFrame&)>;

class FrameSniffer {
public:
    // Begins promiscuous-mode capture. Call once from setup().
    void begin();

    // Stops promiscuous-mode capture.
    void end();

    // Switches the capture channel (1-13). Useful for channel-hopping scans.
    void setChannel(uint8_t channel);

    // Registers a listener that receives every parsed frame.
    // Multiple listeners may be registered (e.g. DeauthDetector, logging).
    void addListener(FrameListener listener);

    // Internal: called by the SDK-level promiscuous callback trampoline.
    // Public so the free-function callback (which the SDK requires to be a
    // plain function pointer, not a class member) can reach it via the
    // singleton instance.
    void handleRawPacket(uint8_t* buf, uint16_t len);

    // Singleton accessor — the ESP8266 SDK promiscuous callback API only
    // accepts a free function pointer, so we route through one instance.
    static FrameSniffer& instance();

private:
    static constexpr size_t MAX_LISTENERS = 8;
    FrameListener _listeners[MAX_LISTENERS];
    size_t _listenerCount = 0;
    uint8_t _currentChannel = 1;

    bool parseManagementFrame(const uint8_t* payload, uint16_t len,
                               int8_t rssi, ParsedFrame& out) const;
};
