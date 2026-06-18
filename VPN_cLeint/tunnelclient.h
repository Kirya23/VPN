#ifndef TUNNELCLIENT_H
#define TUNNELCLIENT_H

#include <QAbstractSocket>
#include <QObject>
#include <QHostAddress>

#include "handshakeprotocol.h"
#include "tunnelcrypto.h"
#include "tunnelprotocol.h"

class QUdpSocket;

enum class TunnelClientState {
    Stopped,
    Handshake,
    Established
};

class TunnelClient : public QObject {
    Q_OBJECT
public:
    explicit TunnelClient(QObject *parent = nullptr);

    bool start(const QString &serverAddress, quint16 serverPort);
    void stop();

    bool isRunning() const { return m_running; }
    bool isSessionEstablished() const { return m_state == TunnelClientState::Established; }
    bool sendIpPacket(const QByteArray &packet);
    bool sendControlPacket(TunnelPacketType type, const QByteArray &payload = QByteArray());

signals:
    void started();
    void stopped();
    void sessionEstablished();
    void ipPacketReceived(const QByteArray &packet);
    void controlFrameReceived(const TunnelFrame &frame);
    void errorOccurred(const QString &error);

private slots:
    void onReadyRead();
    void onSocketError(QAbstractSocket::SocketError socketError);

private:
    bool beginHandshake();
    bool finishHandshake(const TunnelFrame &frame);
    void configurePlatformSocketOptions();
    bool resolveServerAddress(const QString &serverAddress);
    bool sendFrame(const TunnelFrame &frame);

    QUdpSocket *m_socket;
    QHostAddress m_serverAddress;
    quint16 m_serverPort;
    quint32 m_sessionId;
    quint64 m_nextSequence;
    QByteArray m_clientPublicKey;
    QByteArray m_clientPrivateKey;
    QByteArray m_clientRandom;
    TunnelSessionKeys m_sessionKeys;
    bool m_udpResetNoticeShown;
    bool m_running;
    TunnelClientState m_state;
};

#endif // TUNNELCLIENT_H
