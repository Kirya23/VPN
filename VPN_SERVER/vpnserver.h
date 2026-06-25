#ifndef VPNSERVER_H
#define VPNSERVER_H

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QTimer>
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
        qint64 lastActivityMs = 0;
        bool disconnectLogged = false;
    };

    QString peerKey(const QHostAddress &address, quint16 port) const;
    bool sendFrame(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    bool processClientHello(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    bool processEncryptedData(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    void handleKeepalive(const QHostAddress &address, quint16 port, const TunnelFrame &frame);
    void noteClientActivity(ClientSession *session);
    void rememberActiveSession(const QHostAddress &address, quint16 port);
    void onSessionMaintenance();
    void onTunPacketReceived(const QByteArray &packet);
    void onTunError(const QString &error);
    ClientSession *findSession(const QHostAddress &address, quint16 port);
    ClientSession *currentSession();
    ClientSession *activeSession();
    void logSuppressedClientNonIpv4();
    void logSuppressedTunNonIpv4();
    void logSuppressedPacketsWithoutSession(const QHostAddress &address, quint16 port);

    QUdpSocket *m_socket;
    LinuxTunDevice *m_tunDevice;
    QTimer *m_sessionMaintenanceTimer;
    QHash<QString, ClientSession> m_sessions;
    qint64 m_lastClientNonIpv4LogMs = 0;
    qint64 m_lastTunNonIpv4LogMs = 0;
    qint64 m_lastNoSessionLogMs = 0;
    QString m_currentSessionKey;
    int m_suppressedClientNonIpv4Packets = 0;
    int m_suppressedTunNonIpv4Packets = 0;
    int m_suppressedNoSessionPackets = 0;
};

#endif // VPNSERVER_H
