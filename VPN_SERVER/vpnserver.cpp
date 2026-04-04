#include "vpnserver.h"
#include <QDebug>

VpnServer::VpnServer(QObject *parent) : QObject(parent) {
    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &VpnServer::onNewConnection);
}

bool VpnServer::start(quint16 port) {
    if (!server->listen(QHostAddress::Any, port)) {
        qDebug() << "Server error:" << server->errorString();
        return false;
    }
    qDebug() << "Server is listening on port" << port;
    return true;
}

void VpnServer::onNewConnection() {
    QTcpSocket *clientSocket = server->nextPendingConnection();
    qDebug() << "Client connected from:" << clientSocket->peerAddress().toString();

    connect(clientSocket, &QTcpSocket::readyRead, this, [clientSocket]() {
        QByteArray data = clientSocket->readAll();
        qDebug() << "Received:" << data;
        clientSocket->write("Echo: " + data);
    });
}
