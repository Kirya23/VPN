#ifndef TUNNELCLIENT_H
#define TUNNELCLIENT_H

#include <QAbstractSocket>
#include <QObject>
#include <QHostAddress>

#include "tunnelprotocol.h"

class QUdpSocket;

class TunnelClient : public QObject {
    Q_OBJECT
public:
    explicit TunnelClient(QObject *parent = nullptr);

    bool start(const QString &serverAddress, quint16 serverPort);
    void stop();

    bool isRunning() const { return m_running; }
    bool sendIpPacket(const QByteArray &packet);
    bool sendControlPacket(TunnelPacketType type, const QByteArray &payload = QByteArray());

signals:
    void started();
    void stopped();
    void ipPacketReceived(const QByteArray &packet);
    void controlFrameReceived(const TunnelFrame &frame);
    void errorOccurred(const QString &error);

private slots:
    void onReadyRead();
    void onSocketError(QAbstractSocket::SocketError socketError);

private:
    void configurePlatformSocketOptions();
    bool resolveServerAddress(const QString &serverAddress);
    bool sendFrame(const TunnelFrame &frame);

    QUdpSocket *m_socket;
    QHostAddress m_serverAddress;
    quint16 m_serverPort;
    quint32 m_sessionId;
    quint64 m_nextSequence;
    bool m_udpResetNoticeShown;
    bool m_running;
};

#endif // TUNNELCLIENT_H
