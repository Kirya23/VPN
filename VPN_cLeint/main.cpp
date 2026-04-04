#include <QCoreApplication>
#include <QTcpSocket>
#include <QDebug>
#include "wintunadapter.h"

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
        qDebug() << "   Now you can configure routing to send traffic through this adapter";
    }

    void onTunPacketReceived(const QByteArray &packet) {
        qDebug() << "📥 Packet from TUN (size:" << packet.size() << "bytes)";
        // TODO: Зашифровать и отправить на сервер
        socket->write(packet);
    }

    void onTunError(const QString &error) {
        qDebug() << "❌ TUN Adapter error:" << error;
    }

    void onConnected() {
        qDebug() << "✅ Connected to VPN server";
    }

    void onSocketReadyRead() {
        QByteArray data = socket->readAll();
        qDebug() << "📥 Received from server (size:" << data.size() << "bytes)";
        // TODO: Расшифровать и отправить в TUN адаптер
        tunAdapter->sendPacket(data);
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
