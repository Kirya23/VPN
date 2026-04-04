#ifndef VPNSERVER_H
#define VPNSERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QObject>

class VpnServer : public QObject {
    Q_OBJECT
public:
    explicit VpnServer(QObject *parent = nullptr);
    bool start(quint16 port);

private slots:
    void onNewConnection();

private:
    QTcpServer *server;
};

#endif // VPNSERVER_H
