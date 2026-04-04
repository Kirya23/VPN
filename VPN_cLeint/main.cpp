#include <QCoreApplication>
#include <QTcpSocket>
#include <QDebug>
#include <QTimer>
#include <QThread>
#include <QCryptographicHash>
#include "wintunadapter.h"

// Эмуляция TUN адаптера (пока просто генерируем тестовые пакеты)
class SimpleTunEmulator : public QObject {
    Q_OBJECT
public:
    SimpleTunEmulator(WintunAdapter* adapter, QObject *parent = nullptr)
        : QObject(parent), tunAdapter(adapter) {

        // Подключаем сигнал получения пакетов от TUN адаптера
        connect(tunAdapter, &WintunAdapter::packetReceived,
                this, &SimpleTunEmulator::onPacketReceived);
    }

private slots:
    void onPacketReceived(const QByteArray &packet) {
        qDebug() << "📥 Packet from TUN (size:" << packet.size() << "bytes)";
        // Отправляем сигнал с пакетом
        emit packetReady(packet);
    }

signals:
    void packetReady(const QByteArray &packet);

private:
    WintunAdapter* tunAdapter;
};

class VpnClient : public QObject {
    Q_OBJECT
public:
    VpnClient(QObject *parent = nullptr) : QObject(parent) {
        socket = new QTcpSocket(this);
        tunAdapter = new WintunAdapter(this);

        // Подключаем сигналы Wintun адаптера
        connect(tunAdapter, &WintunAdapter::packetReceived,
                this, &VpnClient::onTunPacketReceived);
        connect(tunAdapter, &WintunAdapter::errorOccurred,
                this, &VpnClient::onTunError);
        connect(tunAdapter, &WintunAdapter::adapterReady,
                this, &VpnClient::onTunReady);

        // Подключаем сигналы TCP сокета
        connect(socket, &QTcpSocket::connected, this, &VpnClient::onConnected);
        connect(socket, &QTcpSocket::readyRead, this, &VpnClient::onSocketReadyRead);
        connect(socket, &QTcpSocket::errorOccurred, this, &VpnClient::onSocketError);
    }

    void start(const QString &serverAddress, quint16 port) {
        // Инициализируем и запускаем TUN адаптер
        if (!tunAdapter->initialize("MyVPN")) {
            qDebug() << "Failed to initialize TUN adapter";
            return;
        }

        if (!tunAdapter->start()) {
            qDebug() << "Failed to start TUN adapter";
            return;
        }

        // Подключаемся к VPN серверу
        qDebug() << "Connecting to VPN server at" << serverAddress << ":" << port;
        socket->connectToHost(serverAddress, port);
    }

private slots:
    void onTunReady() {
        qDebug() << "✅ TUN adapter is ready!";
        qDebug() << "   Adapter name:" << tunAdapter->getAdapterName();

        #ifdef Q_OS_WIN
        QThread::sleep(2); // Даём время адаптеру инициализироваться

        // 1. Назначаем IP адаптеру
        QString setIpCmd = QString("netsh interface ip set address \"%1\" static 10.0.0.2 255.255.255.0")
                               .arg(tunAdapter->getAdapterName());
        int result = system(setIpCmd.toLocal8Bit().data());
        if (result == 0) {
            qDebug() << "   ✅ IP address set to 10.0.0.2";
        } else {
            qDebug() << "   ❌ Failed to set IP address (run as administrator!)";
        }

        // 2. Удаляем старый маршрут для 8.8.8.8 если есть
        system("route delete 8.8.8.8 > nul 2>&1");

        // 3. Добавляем тестовый маршрут для ping
        result = system("route add 8.8.8.8 mask 255.255.255.255 10.0.0.1 metric 1");
        if (result == 0) {
            qDebug() << "   ✅ Route added for 8.8.8.8 -> 10.0.0.1";
        } else {
            qDebug() << "   ⚠️ Failed to add route (might already exist)";
        }

        qDebug() << "   → VPN is ready! Try: ping 8.8.8.8";
        #endif
    }

    void onTunPacketReceived(const QByteArray &packet) {
        qDebug() << "📥 Packet from TUN (size:" << packet.size() << "bytes)";

        // Проверяем, открыт ли сокет
        if (socket->state() == QAbstractSocket::ConnectedState) {
            // TODO: Зашифровать пакет
            socket->write(packet);
            qDebug() << "   → Forwarded to server";
        } else {
            qDebug() << "   ⚠️ Socket not connected, packet dropped";
        }
    }

    void onTunError(const QString &error) {
        qDebug() << "❌ TUN Adapter error:" << error;
    }

    void onConnected() {
        qDebug() << "✅ Connected to VPN server!";

        // Отправляем приветствие серверу
        socket->write("VPN_CLIENT_INIT");
    }

    void onSocketReadyRead() {
        QByteArray data = socket->readAll();
        qDebug() << "📥 Received from server (size:" << data.size() << "bytes)";

        // TODO: Расшифровать и отправить в TUN адаптер
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

    qDebug() << "🛡️ VPN Client with Wintun";
    qDebug() << "=========================";

    VpnClient client;
    client.start("127.0.0.1", 8080);

    return a.exec();
}

#include "main.moc"
