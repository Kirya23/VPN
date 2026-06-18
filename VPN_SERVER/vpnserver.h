#ifndef VPNSERVER_H
#define VPNSERVER_H

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QUdpSocket>

#include "handshakeprotocol.h"
#include "linuxtundevice.h"
#include "tunnelcrypto.h"
#include "tunnelprotocol.h"

class VpnServer : public QObject {
    Q_OBJECT
public:
    explicit VpnServer(QObject *parent = nullptr);
    bool start(quint16 port);

private slots:
    void onReadyRead();

private:
    struct ClientSession {
        QHostAddress address;
        quint16 port = 0;
        quint32 sessionId = 0;
        TunnelSessionKeys keys;
        bool established = false;
        QByteArray clientPublicKey;
        QByteArray clientRandom;
        QByteArray serverPublicKey;
        QByteArray serverPrivateKey;
        QByteArray serverRandom;
        quint64 nextServerSequence = 1;
    };

    QString peerKey(const QHostAddress &address, quint16 port) const;
    bool sendFrame(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    bool processClientHello(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    bool processEncryptedData(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    void onTunPacketReceived(const QByteArray &packet);
    void onTunError(const QString &error);
    ClientSession *findSession(const QHostAddress &address, quint16 port);
    ClientSession *activeSession();

    QUdpSocket *m_socket;
    LinuxTunDevice *m_tunDevice;
    QHash<QString, ClientSession> m_sessions;
};

#endif // VPNSERVER_H
