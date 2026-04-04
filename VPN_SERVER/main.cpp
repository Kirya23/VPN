#include <QCoreApplication>
#include "vpnserver.h"

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);
    VpnServer server;
    server.start(8080);
    return a.exec();
}
