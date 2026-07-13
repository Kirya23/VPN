#include "linuxtundevice.h"

#include <cstring>

#include <QDebug>
#include <QProcess>
#include <QSocketNotifier>

#ifdef Q_OS_LINUX
#include <cerrno>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

LinuxTunDevice::LinuxTunDevice(QObject *parent)
    : QObject(parent)
    , m_fd(-1)
    , m_notifier(nullptr)
    , m_running(false)
{
}

LinuxTunDevice::~LinuxTunDevice()
{
    stop();
}

bool LinuxTunDevice::initialize(const QString &deviceName, const QString &localAddress)
{
    m_deviceName = deviceName;
    m_localAddress = localAddress;

#ifndef Q_OS_LINUX
    emit errorOccurred(QStringLiteral("Linux TUN is supported only in the Linux/WSL server build"));
    return false;
#else
    if (m_fd >= 0) {
        return true;
    }

    m_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (m_fd < 0) {
        emit errorOccurred(QStringLiteral("Failed to open /dev/net/tun: %1")
                               .arg(QString::fromLocal8Bit(strerror(errno))));
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    const QByteArray encodedName = deviceName.toLocal8Bit();
    strncpy(ifr.ifr_name, encodedName.constData(), IFNAMSIZ - 1);

    if (ioctl(m_fd, TUNSETIFF, &ifr) < 0) {
        emit errorOccurred(QStringLiteral("Failed to create TUN interface: %1")
                               .arg(QString::fromLocal8Bit(strerror(errno))));
        cleanupFileDescriptor();
        return false;
    }

    m_deviceName = QString::fromLocal8Bit(ifr.ifr_name);
    qDebug() << "[OK] Linux TUN interface created:" << m_deviceName;
    return true;
#endif
}

bool LinuxTunDevice::start()
{
#ifndef Q_OS_LINUX
    return false;
#else
    if (m_running) {
        return true;
    }

    if (m_fd < 0 && !initialize()) {
        return false;
    }

    if (!configureInterface()) {
        cleanupFileDescriptor();
        return false;
    }

    m_notifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_notifier, &QSocketNotifier::activated, this, &LinuxTunDevice::onActivated);

    m_running = true;
    emit ready();
    qDebug() << "[OK] Linux TUN interface is running and ready for IPv4 traffic";
    return true;
#endif
}

void LinuxTunDevice::stop()
{
    if (m_notifier) {
        m_notifier->setEnabled(false);
        m_notifier->deleteLater();
        m_notifier = nullptr;
    }

    m_running = false;
    cleanupFileDescriptor();
}

bool LinuxTunDevice::sendPacket(const QByteArray &packet)
{
#ifndef Q_OS_LINUX
    Q_UNUSED(packet);
    return false;
#else
    if (m_fd < 0) {
        emit errorOccurred(QStringLiteral("TUN interface is not initialized"));
        return false;
    }

    const ssize_t written = write(m_fd, packet.constData(), static_cast<size_t>(packet.size()));
    if (written < 0 || written != packet.size()) {
        emit errorOccurred(QStringLiteral("Failed to write packet into TUN: %1")
                               .arg(QString::fromLocal8Bit(strerror(errno))));
        return false;
    }

    return true;
#endif
}

void LinuxTunDevice::onActivated()
{
#ifdef Q_OS_LINUX
    if (m_fd < 0) {
        return;
    }

    while (true) {
        QByteArray packet(4096, Qt::Uninitialized);
        const ssize_t bytesRead = read(m_fd, packet.data(), static_cast<size_t>(packet.size()));
        if (bytesRead < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            emit errorOccurred(QStringLiteral("Failed to read packet from TUN: %1")
                                   .arg(QString::fromLocal8Bit(strerror(errno))));
            break;
        }

        if (bytesRead == 0) {
            break;
        }

        packet.resize(static_cast<int>(bytesRead));
        emit packetReceived(packet);
    }
#endif
}

bool LinuxTunDevice::configureInterface()
{
#ifndef Q_OS_LINUX
    return false;
#else
    const int linkResult = QProcess::execute(QStringLiteral("ip"),
                                             {QStringLiteral("link"), QStringLiteral("set"), QStringLiteral("dev"),
                                              m_deviceName, QStringLiteral("up")});
    if (linkResult != 0) {
        emit errorOccurred(QStringLiteral("Failed to bring TUN interface %1 up with ip link").arg(m_deviceName));
        return false;
    }

    const int addrResult = QProcess::execute(QStringLiteral("ip"),
                                             {QStringLiteral("addr"), QStringLiteral("replace"), m_localAddress,
                                              QStringLiteral("dev"), m_deviceName});
    if (addrResult != 0) {
        emit errorOccurred(QStringLiteral("Failed to assign address %1 to interface %2")
                               .arg(m_localAddress, m_deviceName));
        return false;
    }

    qDebug() << "[OK] TUN interface" << m_deviceName << "configured with address" << m_localAddress;
    return true;
#endif
}

void LinuxTunDevice::cleanupFileDescriptor()
{
#ifdef Q_OS_LINUX
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
#endif
}
