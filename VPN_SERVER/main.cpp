#include <QCoreApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDebug>
#include <QProcessEnvironment>

#include "vpnserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("VPN_server"));
    QCoreApplication::setApplicationVersion(QStringLiteral("1.0"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("QVPN UDP server"));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption portOption({QStringLiteral("p"), QStringLiteral("port")},
                                  QStringLiteral("UDP port to listen on"),
                                  QStringLiteral("port"),
                                  QStringLiteral("8080"));
    QCommandLineOption tunNameOption(QStringLiteral("tun-name"),
                                     QStringLiteral("Linux TUN interface name"),
                                     QStringLiteral("name"),
                                     QStringLiteral("qvpn0"));
    QCommandLineOption tunAddressOption(QStringLiteral("tun-address"),
                                        QStringLiteral("Linux TUN interface CIDR address"),
                                        QStringLiteral("cidr"),
                                        QStringLiteral("10.10.0.1/24"));

    parser.addOption(portOption);
    parser.addOption(tunNameOption);
    parser.addOption(tunAddressOption);
    parser.process(a);

    const QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

    bool portOk = false;
    const quint16 port = env.value(QStringLiteral("QVPN_PORT"), parser.value(portOption)).toUShort(&portOk);
    if (!portOk || port == 0) {
        qCritical() << "[ERR] Invalid QVPN_PORT/--port value";
        return 1;
    }

    const QString tunName = env.value(QStringLiteral("QVPN_TUN_NAME"), parser.value(tunNameOption));
    const QString tunAddress = env.value(QStringLiteral("QVPN_TUN_ADDRESS"), parser.value(tunAddressOption));

    qDebug() << "[INFO] QVPN server";
    qDebug() << "[INFO] UDP port:" << port;
    qDebug() << "[INFO] TUN device:" << tunName << tunAddress;

    VpnServer server;
    if (!server.start(port, tunName, tunAddress)) {
        return 1;
    }

    return a.exec();
}
