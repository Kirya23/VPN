#ifndef VPNCLIENT_H
#define VPNCLIENT_H

#include <QObject>

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
    void onTunReady();
    void onTunPacketReceived(const QByteArray &packet);
    void onTunnelPacketReceived(const QByteArray &packet);
    void onControlFrameReceived(const TunnelFrame &frame);
    void onTunError(const QString &error);
    void onTunnelError(const QString &error);

private:
    TunnelClient *m_tunnelClient;
    WintunAdapter *m_tunAdapter;
};

#endif // VPNCLIENT_H
