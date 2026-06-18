#include "handshakeprotocol.h"

#include "tunnelcrypto.h"

namespace {

QByteArray encodeHandshakePayload(quint8 kind, const QByteArray &publicKey, const QByteArray &random) {
    QByteArray payload;
    payload.reserve(2 + publicKey.size() + random.size());
    payload.append(static_cast<char>(1)); // Версия handshake
    payload.append(static_cast<char>(kind));
    payload.append(publicKey);
    payload.append(random);
    return payload;
}

bool decodeHandshakePayload(const QByteArray &data,
                            quint8 expectedKind,
                            QByteArray *publicKey,
                            QByteArray *random,
                            QString *error) {
    const int expectedSize = 2 + TunnelCrypto::kPublicKeySize + TunnelCrypto::kRandomSize;
    if (data.size() != expectedSize) {
        if (error) {
            *error = QStringLiteral("Некорректный размер handshake-пакета");
        }
        return false;
    }

    const quint8 version = static_cast<quint8>(data[0]);
    const quint8 kind = static_cast<quint8>(data[1]);

    if (version != 1) {
        if (error) {
            *error = QStringLiteral("Неподдерживаемая версия handshake");
        }
        return false;
    }

    if (kind != expectedKind) {
        if (error) {
            *error = QStringLiteral("Некорректный тип handshake-пакета");
        }
        return false;
    }

    if (publicKey) {
        *publicKey = data.mid(2, TunnelCrypto::kPublicKeySize);
    }
    if (random) {
        *random = data.mid(2 + TunnelCrypto::kPublicKeySize, TunnelCrypto::kRandomSize);
    }

    return true;
}

} // namespace

QByteArray HandshakeProtocol::encodeClientHello(const ClientHelloPayload &payload) {
    return encodeHandshakePayload(1, payload.publicKey, payload.random);
}

bool HandshakeProtocol::decodeClientHello(const QByteArray &data, ClientHelloPayload *payload, QString *error) {
    if (!payload) {
        if (error) {
            *error = QStringLiteral("Выходная структура ClientHello не задана");
        }
        return false;
    }

    return decodeHandshakePayload(data, 1, &payload->publicKey, &payload->random, error);
}

QByteArray HandshakeProtocol::encodeServerHello(const ServerHelloPayload &payload) {
    return encodeHandshakePayload(2, payload.publicKey, payload.random);
}

bool HandshakeProtocol::decodeServerHello(const QByteArray &data, ServerHelloPayload *payload, QString *error) {
    if (!payload) {
        if (error) {
            *error = QStringLiteral("Выходная структура ServerHello не задана");
        }
        return false;
    }

    return decodeHandshakePayload(data, 2, &payload->publicKey, &payload->random, error);
}
