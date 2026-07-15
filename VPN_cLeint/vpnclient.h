#ifndef VPNCLIENT_H
#define VPNCLIENT_H

#include <QObject>
#include <QTimer>

#include "tunnelclient.h"
#include "wintunadapter.h"

class VpnClient : public QObject {
    Q_OBJECT
public:
    explicit VpnClient(QObject *parent = nullptr);
    ~VpnClient();

    bool start(const QString &serverAddress, quint16 port);

private slots:
    void cleanup();
    void onTunnelStarted();
    void onTunnelSessionEstablished();
    void onTunnelConnectionLost();
    void onTunnelConnectionRestored();
    void onReconnectTimer();
    void onTunReady();
    void onTunPacketReceived(const QByteArray &packet);
    void onTunnelPacketReceived(const QByteArray &packet);
    void onControlFrameReceived(const TunnelFrame &frame);
    void onTunError(const QString &error);
    void onTunnelError(const QString &error);

private:
#ifdef Q_OS_WIN
    struct WindowsRouteInfo {
        QString nextHop;
        int interfaceIndex = 0;
        bool isValid() const { return !nextHop.isEmpty() && interfaceIndex > 0; }
    };

    struct WindowsDnsBackup {
        QString interfaceAlias;
        int interfaceIndex = 0;
        int addressFamily = 0;
        QStringList serverAddresses;
        bool hadCustomServers = false;
    };

    bool configureWindowsNetwork(const QString &adapterName);
    bool configureWindowsRoutes(const QString &adapterName);
    bool configureWindowsDns(const QString &adapterName);
    bool overrideNonVpnAdapterDns(const QString &vpnAdapterName);
    void restoreNonVpnAdapterDns();
    bool installServerBypassRoute();
    bool installFullTunnelRoutes(const QString &adapterName);
    bool installLegacyTestRoute(const QString &adapterName);
    void cleanupWindowsRoutes();
    bool runPowerShell(const QString &script, QString *standardOutput = nullptr) const;
    WindowsRouteInfo queryCurrentRouteToServer() const;
    QList<WindowsDnsBackup> queryActiveDnsBackups(const QString &vpnAdapterName) const;
    QString normalizedServerAddress() const;
    QString serverDestinationPrefix() const;
#endif

    TunnelClient *m_tunnelClient;
    WintunAdapter *m_tunAdapter;
    QTimer *m_reconnectTimer;
    QString m_serverAddress;
    quint16 m_serverPort = 0;
    bool m_fullTunnelEnabled = false;
    bool m_serverBypassInstalled = false;
    bool m_legacyTestRouteEnabled = false;
    bool m_reconnectInProgress = false;
    bool m_tunForwardingEnabled = false;
    QList<WindowsDnsBackup> m_dnsBackups;
};

#endif // VPNCLIENT_H
