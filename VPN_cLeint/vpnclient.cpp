#include "vpnclient.h"

#include <QDebug>
#include <QThread>

VpnClient::VpnClient(QObject *parent)
    : QObject(parent)
    , m_tunnelClient(new TunnelClient(this))
    , m_tunAdapter(new WintunAdapter(this))
{
    connect(m_tunAdapter, &WintunAdapter::packetReceived, this, &VpnClient::onTunPacketReceived);
    connect(m_tunAdapter, &WintunAdapter::errorOccurred, this, &VpnClient::onTunError);
    connect(m_tunAdapter, &WintunAdapter::adapterReady, this, &VpnClient::onTunReady);

    connect(m_tunnelClient, &TunnelClient::started, this, &VpnClient::onTunnelStarted);
    connect(m_tunnelClient, &TunnelClient::ipPacketReceived, this, &VpnClient::onTunnelPacketReceived);
    connect(m_tunnelClient, &TunnelClient::controlFrameReceived, this, &VpnClient::onControlFrameReceived);
    connect(m_tunnelClient, &TunnelClient::errorOccurred, this, &VpnClient::onTunnelError);
}

VpnClient::~VpnClient() {
    cleanup();
}

bool VpnClient::start(const QString &serverAddress, quint16 port) {
    qDebug() << "Подключаемся к VPN-серверу" << serverAddress << ":" << port << "по UDP";
    return m_tunnelClient->start(serverAddress, port);
}

void VpnClient::cleanup() {
    qDebug() << "🧹 Очищаем маршруты...";
    m_tunnelClient->stop();
    m_tunAdapter->stop();

#ifdef Q_OS_WIN
    system("route delete 8.8.8.8 > nul 2>&1");
    qDebug() << "   → Маршрут для 8.8.8.8 удалён";
#endif
}

void VpnClient::onTunnelStarted() {
    qDebug() << "✅ Туннельный транспорт запущен";

    if (!m_tunAdapter->initialize("MyVPN")) {
        qDebug() << "Не удалось инициализировать TUN-адаптер";
        return;
    }

    if (!m_tunAdapter->start()) {
        qDebug() << "Не удалось запустить TUN-адаптер";
        return;
    }
}

void VpnClient::onTunReady() {
    qDebug() << "✅ TUN-адаптер готов!";
    qDebug() << "   Имя адаптера:" << m_tunAdapter->getAdapterName();

#ifdef Q_OS_WIN
    QThread::sleep(2);

    const QString adapterName = m_tunAdapter->getAdapterName();

    QString disableIPv6 = QString("netsh interface ipv6 set interface \"%1\" disabled").arg(adapterName);
    system(disableIPv6.toLocal8Bit().data());
    qDebug() << "   ✅ IPv6 отключён на TUN-адаптере";

    QString setIpCmd = QString("netsh interface ip set address \"%1\" static 10.0.0.2 255.255.255.0")
                           .arg(adapterName);
    system(setIpCmd.toLocal8Bit().data());
    qDebug() << "   ✅ IP-адрес 10.0.0.2 назначен";

    system("route delete 8.8.8.8 > nul 2>&1");

    QString psCmd = QString("powershell -Command \"New-NetRoute -DestinationPrefix '8.8.8.8/32' -NextHop '10.0.0.1' -InterfaceAlias '%1' -RouteMetric 1\"")
                        .arg(adapterName);
    const int result = system(psCmd.toLocal8Bit().data());

    if (result == 0) {
        qDebug() << "   ✅ Маршрут для 8.8.8.8 -> 10.0.0.1 добавлен через" << adapterName;
    } else {
        qDebug() << "   ⚠️ Команда PowerShell не сработала, пробуем route add с if 36...";
        system("route add 8.8.8.8 mask 255.255.255.255 10.0.0.1 metric 1 if 36");
    }

    system("route print -4 | findstr \"8.8.8.8\"");

    qDebug() << "   → Клиентская сторона VPN-туннеля готова";
#endif
}

void VpnClient::onTunPacketReceived(const QByteArray &packet) {
    if (packet.size() < 20) {
        return;
    }

    if (!m_tunnelClient->sendIpPacket(packet)) {
        qDebug() << "⚠️ Не удалось передать пакет из TUN в туннельный транспорт";
        return;
    }

    qDebug() << "📥 Пакет из TUN передан в туннель (размер:" << packet.size() << "байт)";
}

void VpnClient::onTunnelPacketReceived(const QByteArray &packet) {
    qDebug() << "📥 IP-пакет получен из туннеля (размер:" << packet.size() << "байт)";

    if (m_tunAdapter->isRunning() && m_tunAdapter->sendPacket(packet)) {
        qDebug() << "   → Пакет передан в TUN-адаптер";
    } else if (m_tunAdapter->isRunning()) {
        qDebug() << "⚠️ Не удалось передать пакет из туннеля в TUN-адаптер";
    }
}

void VpnClient::onControlFrameReceived(const TunnelFrame &frame) {
    qDebug() << "ℹ️ Получен управляющий кадр от сервера. Тип:" << static_cast<int>(frame.type)
             << "Последовательность:" << frame.sequence << "Размер полезной нагрузки:" << frame.payload.size();
}

void VpnClient::onTunError(const QString &error) {
    qDebug() << "❌ Ошибка TUN-адаптера:" << error;
}

void VpnClient::onTunnelError(const QString &error) {
    qDebug() << "❌ Ошибка туннельного транспорта:" << error;
}
