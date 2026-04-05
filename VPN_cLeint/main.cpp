#include <QCoreApplication>
#include <QTcpSocket>
#include <QDebug>
#include <QTimer>
#include <QThread>
#include <csignal>
#include <QRegularExpression>
#include "wintunadapter.h"


// Глобальный указатель для обработки сигналов
static QCoreApplication* globalApp = nullptr;

void signalHandler(int signal) {
    qDebug() << "\n🛑 Received signal" << signal << "- shutting down...";
    if (globalApp) {
        globalApp->quit();
    }
}

class VpnClient : public QObject {
    Q_OBJECT
public:
    VpnClient(QObject *parent = nullptr) : QObject(parent) {
        socket = new QTcpSocket(this);
        tunAdapter = new WintunAdapter(this);

        connect(tunAdapter, &WintunAdapter::packetReceived,
                this, &VpnClient::onTunPacketReceived);
        connect(tunAdapter, &WintunAdapter::errorOccurred,
                this, &VpnClient::onTunError);
        connect(tunAdapter, &WintunAdapter::adapterReady,
                this, &VpnClient::onTunReady);

        connect(socket, &QTcpSocket::connected, this, &VpnClient::onConnected);
        connect(socket, &QTcpSocket::readyRead, this, &VpnClient::onSocketReadyRead);
        connect(socket, &QTcpSocket::errorOccurred, this, &VpnClient::onSocketError);
    }

    ~VpnClient() {
        cleanup();
    }

    void start(const QString &serverAddress, quint16 port) {
        qDebug() << "Connecting to VPN server at" << serverAddress << ":" << port;
        socket->connectToHost(serverAddress, port);
    }

private slots:
    void cleanup() {
        qDebug() << "🧹 Cleaning up routes...";
#ifdef Q_OS_WIN
        system("route delete 8.8.8.8 > nul 2>&1");
        qDebug() << "   → Route removed for 8.8.8.8";
#endif
    }

    void onConnected() {
        qDebug() << "✅ Connected to VPN server!";
        socket->write("VPN_CLIENT_INIT");

        if (!tunAdapter->initialize("MyVPN")) {
            qDebug() << "Failed to initialize TUN adapter";
            return;
        }

        if (!tunAdapter->start()) {
            qDebug() << "Failed to start TUN adapter";
            return;
        }
    }

    void onTunReady() {
        qDebug() << "✅ TUN adapter is ready!";
        qDebug() << "   Adapter name:" << tunAdapter->getAdapterName();

        #ifdef Q_OS_WIN
        QThread::sleep(2);

        QString adapterName = tunAdapter->getAdapterName();

        // 1. Назначаем IP адаптеру
        QString setIpCmd = QString("netsh interface ip set address \"%1\" static 10.0.0.2 255.255.255.0")
                               .arg(adapterName);
        system(setIpCmd.toLocal8Bit().data());
        qDebug() << "   ✅ IP address set to 10.0.0.2";

        // 2. Удаляем старый маршрут
        system("route delete 8.8.8.8 > nul 2>&1");

        // 3. Используем PowerShell для добавления маршрута (автоматически определяет интерфейс)
        QString psCmd = QString("powershell -Command \"New-NetRoute -DestinationPrefix '8.8.8.8/32' -NextHop '10.0.0.1' -InterfaceAlias '%1' -RouteMetric 1\"")
                            .arg(adapterName);
        int result = system(psCmd.toLocal8Bit().data());

        if (result == 0) {
            qDebug() << "   ✅ Route added for 8.8.8.8 -> 10.0.0.1 via" << adapterName;
        } else {
            qDebug() << "   ⚠️ PowerShell failed, trying route command with if 36...";
            system("route add 8.8.8.8 mask 255.255.255.255 10.0.0.1 metric 1 if 36");
        }

        // 4. Проверяем маршрут
        system("route print -4 | findstr \"8.8.8.8\"");

        qDebug() << "   → VPN is ready! Try: ping 8.8.8.8";
        #endif
    }

    void onTunPacketReceived(const QByteArray &packet) {
        qDebug() << "📥 Packet from TUN (size:" << packet.size() << "bytes)";

        if (socket->state() == QAbstractSocket::ConnectedState) {
            socket->write(packet);
            qDebug() << "   → Forwarded to server";
        } else {
            qDebug() << "   ⚠️ Socket not connected, packet dropped";
        }
    }

    void onTunError(const QString &error) {
        qDebug() << "❌ TUN Adapter error:" << error;
    }

    void onSocketReadyRead() {
        QByteArray data = socket->readAll();
        qDebug() << "📥 Received from server (size:" << data.size() << "bytes)";

        if (tunAdapter->isRunning()) {
            tunAdapter->sendPacket(data);
            qDebug() << "   → Forwarded to TUN adapter";
        }
    }

    void onSocketError(QAbstractSocket::SocketError error) {
        qDebug() << "❌ Socket error:" << socket->errorString();
    }

private:
    QTcpSocket *socket;
    WintunAdapter *tunAdapter;
};

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);
    globalApp = &a;

    // Устанавливаем обработчики сигналов для Ctrl+C
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    qDebug() << "🛡️ VPN Client with Wintun";
    qDebug() << "=========================";

    VpnClient client;
    client.start("127.0.0.1", 8080);

    return a.exec();
}

#include "main.moc"
