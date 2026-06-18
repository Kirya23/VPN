#ifndef LINUXTUNDEVICE_H
#define LINUXTUNDEVICE_H

#include <QByteArray>
#include <QObject>
#include <QString>

class QSocketNotifier;

class LinuxTunDevice : public QObject {
    Q_OBJECT
public:
    explicit LinuxTunDevice(QObject *parent = nullptr);
    ~LinuxTunDevice();

    bool initialize(const QString &deviceName = QStringLiteral("qvpn0"),
                    const QString &localAddress = QStringLiteral("10.10.0.1/24"));
    bool start();
    void stop();

    bool isRunning() const { return m_running; }
    QString deviceName() const { return m_deviceName; }
    bool sendPacket(const QByteArray &packet);

signals:
    void packetReceived(const QByteArray &packet);
    void errorOccurred(const QString &error);
    void ready();

private slots:
    void onActivated();

private:
    bool configureInterface();
    void cleanupFileDescriptor();

    int m_fd;
    QSocketNotifier *m_notifier;
    QString m_deviceName;
    QString m_localAddress;
    bool m_running;
};

#endif // LINUXTUNDEVICE_H
