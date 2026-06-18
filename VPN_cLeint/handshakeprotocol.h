#ifndef HANDSHAKEPROTOCOL_H
#define HANDSHAKEPROTOCOL_H

#include <QByteArray>
#include <QString>

struct ClientHelloPayload {
    QByteArray publicKey;
    QByteArray random;
};

struct ServerHelloPayload {
    QByteArray publicKey;
    QByteArray random;
};

class HandshakeProtocol {
public:
    static QByteArray encodeClientHello(const ClientHelloPayload &payload);
    static bool decodeClientHello(const QByteArray &data, ClientHelloPayload *payload, QString *error = nullptr);

    static QByteArray encodeServerHello(const ServerHelloPayload &payload);
    static bool decodeServerHello(const QByteArray &data, ServerHelloPayload *payload, QString *error = nullptr);
};

#endif // HANDSHAKEPROTOCOL_H
