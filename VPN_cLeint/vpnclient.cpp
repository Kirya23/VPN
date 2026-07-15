#include "vpnclient.h"

#include <QDebug>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QThread>

#ifdef Q_OS_WIN
namespace {
constexpr auto kTunnelClientAddress = "10.10.0.2";
constexpr auto kTunnelClientMask = "255.255.255.0";
constexpr auto kTunnelServerAddress = "10.10.0.1";
constexpr auto kTunnelPrimaryDns = "1.1.1.1";
constexpr auto kTunnelSecondaryDns = "8.8.8.8";

QString qstr(const char *value) {
    return QString::fromLatin1(value);
}

QString adapterDisplayName(const QString &alias, int index) {
    if (!alias.trimmed().isEmpty()) {
        return QStringLiteral("\"%1\"").arg(alias);
    }

    if (index > 0) {
        return QStringLiteral("#%1").arg(index);
    }

    return QStringLiteral("<unknown>");
}
}
#endif

VpnClient::VpnClient(QObject *parent)
    : QObject(parent)
    , m_tunnelClient(new TunnelClient(this))
    , m_tunAdapter(new WintunAdapter(this))
    , m_reconnectTimer(new QTimer(this))
{
    connect(m_tunAdapter, &WintunAdapter::packetReceived, this, &VpnClient::onTunPacketReceived);
    connect(m_tunAdapter, &WintunAdapter::errorOccurred, this, &VpnClient::onTunError);
    connect(m_tunAdapter, &WintunAdapter::adapterReady, this, &VpnClient::onTunReady);

    connect(m_tunnelClient, &TunnelClient::started, this, &VpnClient::onTunnelStarted);
    connect(m_tunnelClient, &TunnelClient::sessionEstablished, this, &VpnClient::onTunnelSessionEstablished);
    connect(m_tunnelClient, &TunnelClient::connectionLost, this, &VpnClient::onTunnelConnectionLost);
    connect(m_tunnelClient, &TunnelClient::connectionRestored, this, &VpnClient::onTunnelConnectionRestored);
    connect(m_tunnelClient, &TunnelClient::ipPacketReceived, this, &VpnClient::onTunnelPacketReceived);
    connect(m_tunnelClient, &TunnelClient::controlFrameReceived, this, &VpnClient::onControlFrameReceived);
    connect(m_tunnelClient, &TunnelClient::errorOccurred, this, &VpnClient::onTunnelError);

    m_reconnectTimer->setSingleShot(true);
    m_reconnectTimer->setInterval(2000);
    connect(m_reconnectTimer, &QTimer::timeout, this, &VpnClient::onReconnectTimer);
}

VpnClient::~VpnClient() {
    cleanup();
}

bool VpnClient::start(const QString &serverAddress, quint16 port) {
    m_serverAddress = serverAddress;
    m_serverPort = port;
    m_reconnectInProgress = false;
    m_tunForwardingEnabled = false;
    qDebug() << "Подключаемся к VPN-серверу" << serverAddress << ":" << port << "по UDP";
    return m_tunnelClient->start(serverAddress, port);
}

void VpnClient::cleanup() {
    qDebug() << "[CLEAN] Очищаем маршруты...";

#ifdef Q_OS_WIN
    cleanupWindowsRoutes();
#endif

    m_reconnectTimer->stop();
    m_reconnectInProgress = false;
    m_tunForwardingEnabled = false;
    m_tunnelClient->stop();
    m_tunAdapter->stop();
}

void VpnClient::onTunnelStarted() {
    qDebug() << "[OK] Туннельный транспорт запущен";
    qDebug() << "[WAIT] Ждём подтверждения сессии от сервера перед запуском TUN-адаптера";
}

void VpnClient::onTunnelSessionEstablished() {
    m_reconnectTimer->stop();
    m_reconnectInProgress = false;
    m_tunForwardingEnabled = false;
    qDebug() << "[OK] Туннельная сессия установлена";

    if (!m_tunAdapter->initialize("MyVPN")) {
        qDebug() << "Не удалось инициализировать TUN-адаптер";
        return;
    }

    if (!m_tunAdapter->start()) {
        qDebug() << "Не удалось запустить TUN-адаптер";
        return;
    }
}

void VpnClient::onTunnelConnectionLost() {
    qDebug() << "[ERR] Связь с сервером потеряна";

    if (m_reconnectInProgress) {
        return;
    }

    m_reconnectInProgress = true;
    m_tunForwardingEnabled = false;

#ifdef Q_OS_WIN
    cleanupWindowsRoutes();
#endif
    m_tunAdapter->stop();
    m_tunnelClient->stop();

    qDebug() << "[WAIT] Пытаемся заново установить туннельную сессию...";
    m_reconnectTimer->start();
}

void VpnClient::onTunnelConnectionRestored() {
    qDebug() << "[OK] Связь с сервером восстановлена";
}

void VpnClient::onReconnectTimer() {
    if (m_serverAddress.isEmpty() || m_serverPort == 0) {
        m_reconnectInProgress = false;
        return;
    }

    qDebug() << "[RETRY] Повторное подключение к VPN-серверу" << m_serverAddress << ":" << m_serverPort;
    if (!m_tunnelClient->start(m_serverAddress, m_serverPort)) {
        qDebug() << "[WARN] Повторное подключение не удалось, повторим ещё раз через 2 секунды";
        m_reconnectTimer->start();
    }
}

void VpnClient::onTunReady() {
    qDebug() << "[OK] TUN-адаптер готов!";
    qDebug() << "   Имя адаптера:" << m_tunAdapter->getAdapterName();

#ifdef Q_OS_WIN
    QThread::sleep(2);

    const QString adapterName = m_tunAdapter->getAdapterName();
    if (!configureWindowsNetwork(adapterName)) {
        qDebug() << "   [WARN] Клиентский TUN поднят, но часть сетевой настройки не применена";
        return;
    }

    m_tunForwardingEnabled = true;
    qDebug() << "   [OK] Клиентская сторона VPN-туннеля готова";
#endif
}

void VpnClient::onTunPacketReceived(const QByteArray &packet) {
    if (packet.size() < 20) {
        return;
    }

    if (!m_tunForwardingEnabled || m_reconnectInProgress || !m_tunnelClient->isSessionEstablished()) {
        return;
    }

    if (!m_tunnelClient->sendIpPacket(packet)) {
        qDebug() << "[WARN] Не удалось передать пакет из TUN в туннельный транспорт";
        return;
    }

    qDebug() << "[DATA] Пакет из TUN передан в туннель (размер:" << packet.size() << "байт)";
}

void VpnClient::onTunnelPacketReceived(const QByteArray &packet) {
    qDebug() << "[DATA] IP-пакет получен из туннеля (размер:" << packet.size() << "байт)";

    if (m_tunAdapter->isRunning() && m_tunAdapter->sendPacket(packet)) {
        qDebug() << "   [OK] Пакет передан в TUN-адаптер";
    } else if (m_tunAdapter->isRunning()) {
        qDebug() << "[WARN] Не удалось передать пакет из туннеля в TUN-адаптер";
    }
}

void VpnClient::onControlFrameReceived(const TunnelFrame &frame) {
    qDebug() << "[INFO] Получен управляющий кадр от сервера. Тип:" << static_cast<int>(frame.type)
             << "Последовательность:" << frame.sequence << "Размер полезной нагрузки:" << frame.payload.size();
}

void VpnClient::onTunError(const QString &error) {
    qDebug() << "[ERR] Ошибка TUN-адаптера:" << error;
}

void VpnClient::onTunnelError(const QString &error) {
    qDebug() << "[ERR] Ошибка туннельного транспорта:" << error;
}

#ifdef Q_OS_WIN
bool VpnClient::configureWindowsNetwork(const QString &adapterName) {
    const int disableIpv6Result = QProcess::execute(QStringLiteral("netsh"),
                                                    QStringList{QStringLiteral("interface"), QStringLiteral("ipv6"),
                                                                QStringLiteral("set"), QStringLiteral("interface"),
                                                                adapterName, QStringLiteral("disabled")});
    if (disableIpv6Result == 0) {
        qDebug() << "   [OK] IPv6 отключён на TUN-адаптере";
    } else {
        qDebug() << "   [WARN] Не удалось отключить IPv6 на TUN-адаптере";
    }

    const int setIpResult = QProcess::execute(QStringLiteral("netsh"),
                                              QStringList{QStringLiteral("interface"), QStringLiteral("ip"),
                                                          QStringLiteral("set"), QStringLiteral("address"),
                                                          adapterName, QStringLiteral("static"),
                                                          qstr(kTunnelClientAddress),
                                                          qstr(kTunnelClientMask)});
    if (setIpResult != 0) {
        qDebug() << "   [ERR] Не удалось назначить IP-адрес" << kTunnelClientAddress << "на TUN-адаптер";
        return false;
    }
    qDebug() << "   [OK] IP-адрес" << kTunnelClientAddress << "назначен";

    configureWindowsDns(adapterName);

    if (configureWindowsRoutes(adapterName)) {
        return true;
    }

    qDebug() << "   [WARN] Безопасный full-tunnel пока не применён, откатываемся к тестовому маршруту 8.8.8.8";
    return installLegacyTestRoute(adapterName);
}

bool VpnClient::configureWindowsRoutes(const QString &adapterName) {
    cleanupWindowsRoutes();

    if (!installServerBypassRoute()) {
        qDebug() << "   [ERR] Не удалось создать обходной маршрут до VPS. Без него full-tunnel небезопасен";
        return false;
    }

    if (!installFullTunnelRoutes(adapterName)) {
        qDebug() << "   [ERR] Не удалось включить full-tunnel маршруты через TUN";
        return false;
    }

    m_fullTunnelEnabled = true;
    qDebug() << "   [OK] Весь IPv4-трафик клиента теперь направляется в VPN";
    qDebug() << "   [OK] Отдельный обходной маршрут до VPN-сервера сохранён, чтобы туннель не потерял связь";

    return true;
}

bool VpnClient::configureWindowsDns(const QString &adapterName) {
    const QString script = QStringLiteral(
                               "Set-DnsClientServerAddress -InterfaceAlias '%1' "
                               "-ServerAddresses @('%2','%3')")
                               .arg(adapterName,
                                    qstr(kTunnelPrimaryDns),
                                    qstr(kTunnelSecondaryDns));
    const bool success = runPowerShell(script);
    if (success) {
        qDebug() << "   [OK] DNS для VPN-адаптера настроен:" << kTunnelPrimaryDns << "и" << kTunnelSecondaryDns;
    } else {
        qDebug() << "   [WARN] Не удалось задать DNS на VPN-адаптере. По IP всё ещё можно тестировать";
    }

    const bool nonVpnOverride = overrideNonVpnAdapterDns(adapterName);
    if (nonVpnOverride) {
        qDebug() << "   [OK] DNS на активных не-VPN адаптерах временно выровнен, чтобы уменьшить DNS-утечки";
    } else {
        qDebug() << "   [WARN] Не удалось полностью переопределить DNS на остальных адаптерах. Возможны остаточные DNS-утечки";
    }

    const int flushResult = QProcess::execute(QStringLiteral("ipconfig"), QStringList{QStringLiteral("/flushdns")});
    if (flushResult == 0) {
        qDebug() << "   [OK] Кэш DNS очищен";
    } else {
        qDebug() << "   [WARN] Не удалось очистить кэш DNS";
    }

    return success && nonVpnOverride;
}

bool VpnClient::overrideNonVpnAdapterDns(const QString &vpnAdapterName) {
    restoreNonVpnAdapterDns();
    m_dnsBackups = queryActiveDnsBackups(vpnAdapterName);
    if (m_dnsBackups.isEmpty()) {
        return true;
    }

    bool allSucceeded = true;
    for (const WindowsDnsBackup &backup : std::as_const(m_dnsBackups)) {
        QString script;
        if (backup.addressFamily == 2) {
            script = QStringLiteral(
                         "Set-DnsClientServerAddress -InterfaceIndex %1 "
                         "-ServerAddresses @('%2','%3')")
                         .arg(backup.interfaceIndex)
                         .arg(
                              qstr(kTunnelPrimaryDns),
                              qstr(kTunnelSecondaryDns));
        } else if (backup.addressFamily == 23) {
            script = QStringLiteral(
                         "Set-DnsClientServerAddress -InterfaceIndex %1 "
                         "-ServerAddresses @('2606:4700:4700::1111','2606:4700:4700::1001')")
                         .arg(backup.interfaceIndex);
        } else {
            continue;
        }

        if (!runPowerShell(script)) {
            allSucceeded = false;
            qDebug() << "   [WARN] Не удалось временно переопределить DNS на адаптере"
                     << adapterDisplayName(backup.interfaceAlias, backup.interfaceIndex)
                     << "для семейства адресов" << backup.addressFamily;
        }
    }

    return allSucceeded;
}

void VpnClient::restoreNonVpnAdapterDns() {
    if (m_dnsBackups.isEmpty()) {
        return;
    }

    for (const WindowsDnsBackup &backup : std::as_const(m_dnsBackups)) {
        QString script;
        if (backup.hadCustomServers && !backup.serverAddresses.isEmpty()) {
            QStringList escapedAddresses;
            escapedAddresses.reserve(backup.serverAddresses.size());
            for (const QString &address : backup.serverAddresses) {
                escapedAddresses << QStringLiteral("'%1'").arg(address);
            }

            script = QStringLiteral(
                         "Set-DnsClientServerAddress -InterfaceIndex %1 -ServerAddresses @(%2)")
                         .arg(backup.interfaceIndex)
                         .arg(escapedAddresses.join(QStringLiteral(",")));
        } else {
            script = QStringLiteral(
                         "Set-DnsClientServerAddress -InterfaceIndex %1 -ResetServerAddresses")
                         .arg(backup.interfaceIndex);
        }

        if (!runPowerShell(script)) {
            qDebug() << "   [WARN] Не удалось восстановить исходный DNS на адаптере"
                     << adapterDisplayName(backup.interfaceAlias, backup.interfaceIndex);
        }
    }

    m_dnsBackups.clear();
}

bool VpnClient::installServerBypassRoute() {
    const QString serverIp = normalizedServerAddress();
    if (serverIp.isEmpty()) {
        qDebug() << "   [ERR] Адрес VPN-сервера не является IPv4-адресом. Для текущего MVP нужен прямой IPv4";
        return false;
    }

    const WindowsRouteInfo currentRoute = queryCurrentRouteToServer();
    if (!currentRoute.isValid()) {
        qDebug() << "   [ERR] Не удалось определить текущий системный маршрут до VPN-сервера" << serverIp;
        return false;
    }

    const QString removeScript = QStringLiteral(
                                     "Get-NetRoute -DestinationPrefix '%1/32' -ErrorAction SilentlyContinue | "
                                     "Remove-NetRoute -Confirm:$false")
                                     .arg(serverIp);
    runPowerShell(removeScript);

    const QString addScript = QStringLiteral(
                                  "New-NetRoute -DestinationPrefix '%1/32' -NextHop '%2' "
                                  "-InterfaceIndex %3 -RouteMetric 1")
                                  .arg(serverIp, currentRoute.nextHop)
                                  .arg(currentRoute.interfaceIndex);
    if (!runPowerShell(addScript)) {
        return false;
    }

    m_serverBypassInstalled = true;
    qDebug() << "   [OK] Обходной маршрут до VPN-сервера" << serverIp
             << "оставлен через исходный шлюз" << currentRoute.nextHop;
    return true;
}

bool VpnClient::installFullTunnelRoutes(const QString &adapterName) {
    const QString removeScript =
        QStringLiteral(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.NextHop -eq '%1' } | Remove-NetRoute -Confirm:$false; "
            "Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.NextHop -eq '%1' } | Remove-NetRoute -Confirm:$false")
            .arg(qstr(kTunnelServerAddress));
    runPowerShell(removeScript);

    const QString firstHalfScript = QStringLiteral(
                                        "New-NetRoute -DestinationPrefix '0.0.0.0/1' -NextHop '%1' "
                                        "-InterfaceAlias '%2' -RouteMetric 1")
                                        .arg(qstr(kTunnelServerAddress), adapterName);
    const QString secondHalfScript = QStringLiteral(
                                         "New-NetRoute -DestinationPrefix '128.0.0.0/1' -NextHop '%1' "
                                         "-InterfaceAlias '%2' -RouteMetric 1")
                                         .arg(qstr(kTunnelServerAddress), adapterName);

    return runPowerShell(firstHalfScript) && runPowerShell(secondHalfScript);
}

bool VpnClient::installLegacyTestRoute(const QString &adapterName) {
    const QString removeScript = QStringLiteral(
                                     "Get-NetRoute -DestinationPrefix '8.8.8.8/32' -ErrorAction SilentlyContinue | "
                                     "Remove-NetRoute -Confirm:$false");
    runPowerShell(removeScript);

    const QString addScript = QStringLiteral(
                                  "New-NetRoute -DestinationPrefix '8.8.8.8/32' -NextHop '%1' "
                                  "-InterfaceAlias '%2' -RouteMetric 1")
                                  .arg(qstr(kTunnelServerAddress), adapterName);
    if (!runPowerShell(addScript)) {
        qDebug() << "   [ERR] Даже тестовый маршрут 8.8.8.8 через VPN не удалось добавить";
        return false;
    }

    m_legacyTestRouteEnabled = true;
    qDebug() << "   [OK] Маршрут для 8.8.8.8 ->" << kTunnelServerAddress << "добавлен через" << adapterName;
    return true;
}

void VpnClient::cleanupWindowsRoutes() {
    const QString serverIp = normalizedServerAddress();

    restoreNonVpnAdapterDns();

    runPowerShell(QStringLiteral(
                      "Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | "
                      "Where-Object { $_.NextHop -eq '%1' } | Remove-NetRoute -Confirm:$false; "
                      "Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | "
                      "Where-Object { $_.NextHop -eq '%1' } | Remove-NetRoute -Confirm:$false; "
                      "Get-NetRoute -DestinationPrefix '8.8.8.8/32' -ErrorAction SilentlyContinue | "
                      "Where-Object { $_.NextHop -eq '%1' } | Remove-NetRoute -Confirm:$false")
                      .arg(qstr(kTunnelServerAddress)));

    if (!serverIp.isEmpty()) {
        runPowerShell(QStringLiteral(
                          "Get-NetRoute -DestinationPrefix '%1/32' -ErrorAction SilentlyContinue | "
                          "Remove-NetRoute -Confirm:$false")
                          .arg(serverIp));
    }

    if (m_fullTunnelEnabled) {
        qDebug() << "   [CLEAN] Full-tunnel маршруты удалены";
    }
    if (m_serverBypassInstalled) {
        qDebug() << "   [CLEAN] Обходной маршрут до VPN-сервера удалён";
    }
    if (m_legacyTestRouteEnabled) {
        qDebug() << "   [CLEAN] Тестовый маршрут 8.8.8.8 удалён";
    }

    m_fullTunnelEnabled = false;
    m_serverBypassInstalled = false;
    m_legacyTestRouteEnabled = false;
}

bool VpnClient::runPowerShell(const QString &script, QString *standardOutput) const {
    QProcess process;
    process.start(QStringLiteral("powershell"),
                  QStringList{QStringLiteral("-NoProfile"),
                              QStringLiteral("-ExecutionPolicy"), QStringLiteral("Bypass"),
                              QStringLiteral("-Command"), script});

    if (!process.waitForFinished(15000)) {
        qDebug() << "   [ERR] PowerShell-команда не завершилась вовремя";
        return false;
    }

    if (standardOutput) {
        *standardOutput = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
    }

    const QString standardError = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (!standardError.isEmpty()) {
            const QStringList lines = standardError.split(QRegularExpression(QStringLiteral("[\r\n]+")),
                                                          Qt::SkipEmptyParts);
            qDebug() << "   [WARN] PowerShell завершился с ошибкой:" << lines.value(0, standardError);
        } else {
            qDebug() << "   [WARN] PowerShell завершился с ошибкой, код:" << process.exitCode();
        }
        return false;
    }

    return true;
}

VpnClient::WindowsRouteInfo VpnClient::queryCurrentRouteToServer() const {
    WindowsRouteInfo info;
    const QString serverIp = normalizedServerAddress();
    if (serverIp.isEmpty()) {
        return info;
    }

    const QString script = QStringLiteral(
                               "$route = Find-NetRoute -RemoteIPAddress '%1' | "
                               "Where-Object { $_.DestinationPrefix -notlike '*:*' -and $_.NextHop -match '^[0-9]+\\.' } | "
                               "Sort-Object -Property RouteMetric,InterfaceMetric | Select-Object -First 1; "
                               "if ($null -eq $route) { exit 1 }; "
                               "[pscustomobject]@{ NextHop = $route.NextHop; InterfaceIndex = $route.InterfaceIndex } | "
                               "ConvertTo-Json -Compress")
                               .arg(serverIp);

    QString output;
    if (!runPowerShell(script, &output) || output.isEmpty()) {
        return info;
    }

    const QJsonDocument json = QJsonDocument::fromJson(output.toUtf8());
    if (!json.isObject()) {
        return info;
    }

    const QJsonObject object = json.object();
    info.nextHop = object.value(QStringLiteral("NextHop")).toString().trimmed();
    info.interfaceIndex = object.value(QStringLiteral("InterfaceIndex")).toInt();
    return info;
}

QList<VpnClient::WindowsDnsBackup> VpnClient::queryActiveDnsBackups(const QString &vpnAdapterName) const {
    QList<WindowsDnsBackup> backups;
    const QString script = QStringLiteral(
                               "Get-DnsClientServerAddress | "
                               "Where-Object { $_.InterfaceAlias -ne '%1' -and $_.ServerAddresses.Count -gt 0 } | "
                               "ForEach-Object { "
                               "  $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
                               "  if ($adapter -and $adapter.Status -eq 'Up') { "
                               "    [pscustomobject]@{ "
                               "      InterfaceAlias = $_.InterfaceAlias; "
                               "      InterfaceIndex = $_.InterfaceIndex; "
                               "      AddressFamily = $_.AddressFamily; "
                               "      ServerAddresses = $_.ServerAddresses "
                               "    } "
                               "  } "
                               "} | ConvertTo-Json -Compress")
                               .arg(vpnAdapterName);

    QString output;
    if (!runPowerShell(script, &output) || output.isEmpty()) {
        return backups;
    }

    const QJsonDocument json = QJsonDocument::fromJson(output.toUtf8());
    if (json.isNull()) {
        return backups;
    }

    auto appendBackup = [&backups](const QJsonObject &object) {
        WindowsDnsBackup backup;
        backup.interfaceAlias = object.value(QStringLiteral("InterfaceAlias")).toString();
        backup.interfaceIndex = object.value(QStringLiteral("InterfaceIndex")).toInt();
        backup.addressFamily = object.value(QStringLiteral("AddressFamily")).toInt();

        const QJsonValue serverAddressesValue = object.value(QStringLiteral("ServerAddresses"));
        if (serverAddressesValue.isArray()) {
            const QJsonArray array = serverAddressesValue.toArray();
            for (const QJsonValue &value : array) {
                const QString address = value.toString().trimmed();
                if (!address.isEmpty()) {
                    backup.serverAddresses << address;
                }
            }
        } else {
            const QString address = serverAddressesValue.toString().trimmed();
            if (!address.isEmpty()) {
                backup.serverAddresses << address;
            }
        }

        backup.hadCustomServers = !backup.serverAddresses.isEmpty();
        if (backup.interfaceIndex > 0 && backup.addressFamily != 0) {
            backups << backup;
        }
    };

    if (json.isArray()) {
        const QJsonArray array = json.array();
        for (const QJsonValue &value : array) {
            if (value.isObject()) {
                appendBackup(value.toObject());
            }
        }
    } else if (json.isObject()) {
        appendBackup(json.object());
    }

    return backups;
}

QString VpnClient::normalizedServerAddress() const {
    const QHostAddress address(m_serverAddress);
    if (address.isNull() || address.protocol() != QAbstractSocket::IPv4Protocol) {
        return QString();
    }
    return address.toString();
}

QString VpnClient::serverDestinationPrefix() const {
    const QString serverIp = normalizedServerAddress();
    if (serverIp.isEmpty()) {
        return QString();
    }
    return serverIp + QStringLiteral("/32");
}
#endif
