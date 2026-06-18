#include <QCoreApplication>
#include <QDebug>
#include "vpnserver.h"

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    qDebug() << "🛡️ VPN-сервер";
    qDebug() << "==============";

    VpnServer server;
    server.start(8080);
    return a.exec();
}
