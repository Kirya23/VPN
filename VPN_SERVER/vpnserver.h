#ifndef VPNSERVER_H
#define VPNSERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QMap>
#include <QObject>

class VpnServer : public QObject {
    Q_OBJECT
public:
    explicit VpnServer(QObject *parent = nullptr);
    bool start(quint16 port);

private slots:
    void onNewConnection();

private:
    void handlePacket(QTcpSocket* clientSocket, const QByteArray& packet);
    void forwardToInternet(QTcpSocket* clientSocket, const QByteArray& ipPacket);

    // Обработка разных протоколов
    void handleTCP(QTcpSocket* clientSocket, const QByteArray& packet);
    void handleUDP(QTcpSocket* clientSocket, const QByteArray& packet);
    void handleICMP(QTcpSocket* clientSocket, const QByteArray& packet);

    void handleICMPv6(QTcpSocket* clientSocket, const QByteArray& packet);
    void handleUDPv6(QTcpSocket* clientSocket, const QByteArray& packet);

    // Вспомогательные функции
    quint32 extractDestIP(const QByteArray& packet);
    quint16 extractDestPort(const QByteArray& packet);
    QByteArray createIPResponse(const QByteArray& originalPacket, const QByteArray& payload);

    QTcpServer *server;

    // Хранилище UDP сокетов для каждого клиента
    struct UDPConnection {
        QUdpSocket* socket;
        QTcpSocket* clientSocket;
        QHostAddress targetAddress;
        quint16 targetPort;
    };
    QMap<quint64, UDPConnection> udpConnections;

    quint64 getConnectionId(const QHostAddress& addr, quint16 port);
};

#endif // VPNSERVER_H
