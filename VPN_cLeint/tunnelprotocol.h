#ifndef TUNNELPROTOCOL_H
#define TUNNELPROTOCOL_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

enum class TunnelPacketType : quint8 {
    ClientHello = 1,
    ServerHello = 2,
    Data = 3,
    Keepalive = 4,
    Error = 5
};

struct TunnelFrame {
    TunnelPacketType type = TunnelPacketType::Data;
    quint8 flags = 0;
    quint32 sessionId = 0;
    quint64 sequence = 0;
    QByteArray payload;
    QByteArray authTag;
};

class TunnelProtocol {
public:
    static constexpr quint32 kMagic = 0x56504E31; // "VPN1"
    static constexpr quint8 kVersion = 1;
    static constexpr quint8 kFlagEncrypted = 0x01;
    static constexpr int kHeaderSize = 22;
    static constexpr int kAuthTagSize = 16;

    static QByteArray encodeFrame(const TunnelFrame &frame);
    static QByteArray encodeHeader(const TunnelFrame &frame, quint16 payloadLength);
    static bool decodeFrame(const QByteArray &datagram, TunnelFrame *frame, QString *error = nullptr);
};

#endif // TUNNELPROTOCOL_H
