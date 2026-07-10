#include "FrameSniffer.h"

extern "C" {
#include "user_interface.h"
}

// The ESP8266 non-OS SDK delivers promiscuous management frames in this
// layout (no radiotap header, unlike Linux monitor mode). This struct
// mirrors the SDK's documented sniffer buffer for management frames.
struct SdkRxControl {
    signed  rssi : 8;
    unsigned rate : 4;
    unsigned is_group : 1;
    unsigned : 1;
    unsigned sig_mode : 2;
    unsigned legacy_length : 12;
    unsigned damatch0 : 1;
    unsigned damatch1 : 1;
    unsigned bssidmatch0 : 1;
    unsigned bssidmatch1 : 1;
    unsigned MCS : 7;
    unsigned CWB : 1;
    unsigned HT_length : 16;
    unsigned Smoothing : 1;
    unsigned Not_Sounding : 1;
    unsigned : 1;
    unsigned Aggregation : 1;
    unsigned STBC : 2;
    unsigned FEC_CODING : 1;
    unsigned SGI : 1;
    unsigned rxend_state : 8;
    unsigned ampdu_cnt : 8;
    unsigned channel : 4;
    unsigned : 12;
};

struct SdkSnifferBuf {
    SdkRxControl rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;
};

// Offsets within the 802.11 MAC header (buf[]), per IEEE 802.11-2020 9.2.4.
namespace HeaderOffset {
    constexpr int FRAME_CONTROL = 0;
    constexpr int ADDR1_DEST    = 4;
    constexpr int ADDR2_SRC     = 10;
    constexpr int ADDR3_BSSID   = 16;
    constexpr int SEQ_CONTROL   = 22;
    constexpr int MIN_HEADER_LEN = 24;
}

FrameSniffer& FrameSniffer::instance() {
    static FrameSniffer sniffer;
    return sniffer;
}

// Free-function trampoline required by the SDK's callback signature.
static void IRAM_ATTR promiscuousCallback(uint8_t* buf, uint16_t len) {
    FrameSniffer::instance().handleRawPacket(buf, len);
}

void FrameSniffer::begin() {
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promiscuousCallback);
    wifi_set_channel(_currentChannel);
    wifi_promiscuous_enable(1);
}

void FrameSniffer::end() {
    wifi_promiscuous_enable(0);
}

void FrameSniffer::setChannel(uint8_t channel) {
    if (channel < 1 || channel > 13) return;
    _currentChannel = channel;
    wifi_set_channel(_currentChannel);
}

void FrameSniffer::addListener(FrameListener listener) {
    if (_listenerCount < MAX_LISTENERS) {
        _listeners[_listenerCount++] = listener;
    }
}

bool FrameSniffer::parseManagementFrame(const uint8_t* payload, uint16_t len,
                                         int8_t rssi, ParsedFrame& out) const {
    if (len < HeaderOffset::MIN_HEADER_LEN) return false;

    uint8_t frameControl0 = payload[HeaderOffset::FRAME_CONTROL];
    uint8_t typeAndSubtype = frameControl0 & Dot11::TYPE_MASK;

    // Only management-frame subtypes we currently act on. Extend this list
    // as detectors are added (e.g. probe requests for client tracking).
    switch (typeAndSubtype) {
        case Dot11::SUBTYPE_BEACON:
        case Dot11::SUBTYPE_PROBE_REQ:
        case Dot11::SUBTYPE_PROBE_RESP:
        case Dot11::SUBTYPE_DEAUTH:
        case Dot11::SUBTYPE_DISASSOC:
            out.frameSubtype = typeAndSubtype;
            break;
        default:
            return false; // not a frame type this project analyzes
    }

    memcpy(out.destMac, &payload[HeaderOffset::ADDR1_DEST], 6);
    memcpy(out.srcMac,  &payload[HeaderOffset::ADDR2_SRC], 6);
    memcpy(out.bssid,   &payload[HeaderOffset::ADDR3_BSSID], 6);

    uint16_t seqControl = payload[HeaderOffset::SEQ_CONTROL] |
                           (payload[HeaderOffset::SEQ_CONTROL + 1] << 8);
    out.seqNum = seqControl >> 4; // top 12 bits are the sequence number

    out.rssi = rssi;
    out.timestampMs = millis();

    return true;
}

void FrameSniffer::handleRawPacket(uint8_t* buf, uint16_t len) {
    // The SDK's generic promiscuous buffer starts with a 1-byte type field
    // in some SDK versions when using the "long" callback signature; the
    // widely-used pattern for management frames is to interpret the whole
    // buffer as SdkSnifferBuf, as this project does. Adjust here if you're
    // targeting a different SDK version.
    if (len < sizeof(SdkSnifferBuf) - sizeof(SdkSnifferBuf::buf)) return;

    auto* sniffBuf = reinterpret_cast<SdkSnifferBuf*>(buf);

    ParsedFrame parsed{};
    parsed.channel = sniffBuf->rx_ctrl.channel;

    if (!parseManagementFrame(sniffBuf->buf, sniffBuf->len,
                               sniffBuf->rx_ctrl.rssi, parsed)) {
        return;
    }

    for (size_t i = 0; i < _listenerCount; i++) {
        _listeners[i](parsed);
    }
}
