#include "tunnelprotocol.h"

#include <cstring>
#include <QtEndian>

namespace {

void appendUint16(QByteArray *buffer, quint16 value) {
    const quint16 networkValue = qToBigEndian(value);
    buffer->append(reinterpret_cast<const char *>(&networkValue), sizeof(networkValue));
}

void appendUint32(QByteArray *buffer, quint32 value) {
    const quint32 networkValue = qToBigEndian(value);
    buffer->append(reinterpret_cast<const char *>(&networkValue), sizeof(networkValue));
}

void appendUint64(QByteArray *buffer, quint64 value) {
    const quint64 networkValue = qToBigEndian(value);
    buffer->append(reinterpret_cast<const char *>(&networkValue), sizeof(networkValue));
}

quint16 readUint16(const char *data) {
    quint16 value = 0;
    memcpy(&value, data, sizeof(value));
    return qFromBigEndian(value);
}

quint32 readUint32(const char *data) {
    quint32 value = 0;
    memcpy(&value, data, sizeof(value));
    return qFromBigEndian(value);
}

quint64 readUint64(const char *data) {
    quint64 value = 0;
    memcpy(&value, data, sizeof(value));
    return qFromBigEndian(value);
}

} // namespace

QByteArray TunnelProtocol::encodeFrame(const TunnelFrame &frame) {
    QByteArray encoded;
    encoded.reserve(kHeaderSize + frame.payload.size());

    appendUint32(&encoded, kMagic);
    encoded.append(static_cast<char>(kVersion));
    encoded.append(static_cast<char>(frame.type));
    encoded.append(static_cast<char>(frame.flags));
    encoded.append(char(0));
    appendUint32(&encoded, frame.sessionId);
    appendUint64(&encoded, frame.sequence);
    appendUint16(&encoded, static_cast<quint16>(frame.payload.size()));
    encoded.append(frame.payload);

    return encoded;
}

bool TunnelProtocol::decodeFrame(const QByteArray &datagram, TunnelFrame *frame, QString *error) {
    if (!frame) {
        if (error) {
            *error = QStringLiteral("Указатель для выходного кадра равен null");
        }
        return false;
    }

    if (datagram.size() < kHeaderSize) {
        if (error) {
            *error = QStringLiteral("Датаграмма меньше заголовка туннеля");
        }
        return false;
    }

    const char *data = datagram.constData();
    const quint32 magic = readUint32(data);
    if (magic != kMagic) {
        if (error) {
            *error = QStringLiteral("Некорректная сигнатура туннеля");
        }
        return false;
    }

    const quint8 version = static_cast<quint8>(data[4]);
    if (version != kVersion) {
        if (error) {
            *error = QStringLiteral("Неподдерживаемая версия туннеля");
        }
        return false;
    }

    const quint16 payloadLength = readUint16(data + 20);
    if (datagram.size() != kHeaderSize + payloadLength) {
        if (error) {
            *error = QStringLiteral("Длина датаграммы не совпадает с заголовком туннеля");
        }
        return false;
    }

    frame->type = static_cast<TunnelPacketType>(static_cast<quint8>(data[5]));
    frame->flags = static_cast<quint8>(data[6]);
    frame->sessionId = readUint32(data + 8);
    frame->sequence = readUint64(data + 12);
    frame->payload = datagram.mid(kHeaderSize, payloadLength);

    return true;
}
