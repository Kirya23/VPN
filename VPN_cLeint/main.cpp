#include <QTcpSocket>
#include <QCoreApplication>
#include <QDebug>
#include <QTimer>

class VpnClient : public QObject {
    Q_OBJECT
public:
    VpnClient(QObject *parent = nullptr) : QObject(parent) {
        socket = new QTcpSocket(this);
        // Обработка успешного подключения
        connect(socket, &QTcpSocket::connected, this, &VpnClient::onConnected);
        // Обработка получения данных от сервера
        connect(socket, &QTcpSocket::readyRead, this, &VpnClient::onReadyRead);
        // Обработка ошибок
        connect(socket, &QTcpSocket::errorOccurred, this, &VpnClient::onError);
    }

    void connectToServer(const QString &address, quint16 port) {
        qDebug() << "Connecting to" << address << ":" << port;
        socket->connectToHost(address, port);
    }

private slots:
    void onConnected() {
        qDebug() << "Connected to server!";
        // Отправляем тестовое сообщение
        socket->write("Hello, VPN Server!");
    }

    void onReadyRead() {
        QByteArray data = socket->readAll();
        qDebug() << "Server response:" << data;
        QCoreApplication::quit(); // Завершаем после ответа
    }

    void onError(QAbstractSocket::SocketError) {
        qDebug() << "Socket error:" << socket->errorString();
    }

private:
    QTcpSocket *socket;
};

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);
    VpnClient client;
    client.connectToServer("127.0.0.1", 8080);
    return a.exec();
}

#include "main.moc"
