#include "vpnserver.h"

#include <QDateTime>
#include <QDebug>
#include <QtEndian>

namespace {
constexpr qint64 kClientSessionIdleTimeoutMs = 60000;
}

VpnServer::VpnServer(QObject *parent)
    : QObject(parent)
    , m_socket(new QUdpSocket(this))
    , m_tunDevice(new LinuxTunDevice(this))
    , m_sessionMaintenanceTimer(new QTimer(this))
{
    connect(m_socket, &QUdpSocket::readyRead, this, &VpnServer::onReadyRead);
    connect(m_tunDevice, &LinuxTunDevice::packetReceived, this, &VpnServer::onTunPacketReceived);
    connect(m_tunDevice, &LinuxTunDevice::errorOccurred, this, &VpnServer::onTunError);
    m_sessionMaintenanceTimer->setInterval(1000);
    connect(m_sessionMaintenanceTimer, &QTimer::timeout, this, &VpnServer::onSessionMaintenance);
}

bool VpnServer::start(quint16 port, const QString &tunName, const QString &tunAddress)
{
    if (!m_socket->bind(QHostAddress::AnyIPv4, port)) {
        qCritical() << "[ERR] Failed to start UDP server:" << m_socket->errorString();
        return false;
    }
    qDebug() << "[OK] UDP server is listening on port" << port;

    if (m_tunDevice->initialize(tunName, tunAddress)) {
        if (!m_tunDevice->start()) {
            qWarning() << "[WARN] Linux TUN backend is not running, server will stay in protocol-only mode";
        }
    } else {
        qWarning() << "[WARN] Linux TUN backend is not available in this build or environment";
    }

    m_sessionMaintenanceTimer->start();
    return true;
}

void VpnServer::onReadyRead()
{
    while (m_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(static_cast<int>(m_socket->pendingDatagramSize()));

        QHostAddress senderAddress;
        quint16 senderPort = 0;
        if (m_socket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort) < 0) {
            qWarning() << "[WARN] Failed to read UDP datagram:" << m_socket->errorString();
            continue;
        }

        TunnelFrame frame;
        QString error;
        if (!TunnelProtocol::decodeFrame(datagram, &frame, &error)) {
            qWarning() << "[WARN] Failed to decode tunnel datagram from"
                       << senderAddress.toString() << ":" << senderPort << "-" << error;
            continue;
        }

        if (frame.type == TunnelPacketType::ClientHello) {
            processClientHello(senderAddress, senderPort, frame);
            continue;
        }

        if (frame.type == TunnelPacketType::Keepalive) {
            handleKeepalive(senderAddress, senderPort, frame);
            continue;
        }

        if (frame.type == TunnelPacketType::Data) {
            processEncryptedData(senderAddress, senderPort, frame);
            continue;
        }

        qDebug() << "[INFO] Received control frame from" << senderAddress.toString() << ":" << senderPort
                 << "type:" << static_cast<int>(frame.type);
    }
}

QString VpnServer::peerKey(const QHostAddress &address, quint16 port) const
{
    return QStringLiteral("%1:%2").arg(address.toString()).arg(port);
}

bool VpnServer::sendFrame(const QHostAddress &address, quint16 port, const TunnelFrame &frame)
{
    const QByteArray datagram = TunnelProtocol::encodeFrame(frame);
    const qint64 bytesSent = m_socket->writeDatagram(datagram, address, port);
    if (bytesSent != datagram.size()) {
        qWarning() << "[WARN] Failed to send UDP datagram to"
                   << address.toString() << ":" << port << "-" << m_socket->errorString();
        return false;
    }
    return true;
}

bool VpnServer::processClientHello(const QHostAddress &address, quint16 port, const TunnelFrame &frame)
{
    ClientHelloPayload clientHello;
    QString error;
    if (!HandshakeProtocol::decodeClientHello(frame.payload, &clientHello, &error)) {
        qWarning() << "[WARN] Invalid ClientHello from" << address.toString() << ":" << port << "-" << error;
        return false;
    }

    ClientSession session;
    session.address = address;
    session.port = port;
    session.clientPublicKey = clientHello.publicKey;
    session.clientRandom = clientHello.random;

    if (!TunnelCrypto::generateX25519KeyPair(&session.serverPublicKey, &session.serverPrivateKey, &error)) {
        qCritical() << "[ERR] Failed to generate server key pair:" << error;
        return false;
    }

    if (!TunnelCrypto::randomBytes(TunnelCrypto::kRandomSize, &session.serverRandom, &error)) {
        qCritical() << "[ERR] Failed to generate server random value:" << error;
        return false;
    }

    QByteArray sessionIdBytes;
    if (!TunnelCrypto::randomBytes(sizeof(quint32), &sessionIdBytes, &error)) {
        qCritical() << "[ERR] Failed to generate session id:" << error;
        return false;
    }

    session.sessionId = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(sessionIdBytes.constData()));
    if (session.sessionId == 0) {
        session.sessionId = 1;
    }

    if (!TunnelCrypto::deriveServerSessionKeys(session.serverPrivateKey,
                                               session.serverPublicKey,
                                               session.serverRandom,
                                               session.clientPublicKey,
                                               session.clientRandom,
                                               &session.keys,
                                               &error)) {
        qCritical() << "[ERR] Failed to derive session keys:" << error;
        return false;
    }

    session.established = true;
    session.lastActivityMs = QDateTime::currentMSecsSinceEpoch();
    m_sessions.insert(peerKey(address, port), session);
    rememberActiveSession(address, port);

    ServerHelloPayload serverHello;
    serverHello.publicKey = session.serverPublicKey;
    serverHello.random = session.serverRandom;

    TunnelFrame response;
    response.type = TunnelPacketType::ServerHello;
    response.sessionId = session.sessionId;
    response.sequence = 1;
    response.payload = HandshakeProtocol::encodeServerHello(serverHello);

    qDebug() << "[OK] Handshake completed with" << address.toString() << ":" << port
             << "session id:" << session.sessionId;

    return sendFrame(address, port, response);
}

bool VpnServer::processEncryptedData(const QHostAddress &address, quint16 port, const TunnelFrame &frame)
{
    ClientSession *session = findSession(address, port);
    if (!session || !session->established) {
        logSuppressedPacketsWithoutSession(address, port);
        return false;
    }

    if (frame.sessionId != session->sessionId) {
        qWarning() << "[WARN] Invalid session id from" << address.toString() << ":" << port
                   << "expected:" << session->sessionId << "received:" << frame.sessionId;
        return false;
    }

    if ((frame.flags & TunnelProtocol::kFlagEncrypted) == 0) {
        qWarning() << "[WARN] Received unencrypted data packet from"
                   << address.toString() << ":" << port;
        return false;
    }

    const QByteArray aad = TunnelProtocol::encodeHeader(frame, static_cast<quint16>(frame.payload.size()));
    QByteArray plaintext;
    QString error;
    if (!TunnelCrypto::decryptPacket(session->keys.rxKey,
                                     session->keys.rxNoncePrefix,
                                     frame.sequence,
                                     aad,
                                     frame.payload,
                                     frame.authTag,
                                     &plaintext,
                                     &error)) {
        qWarning() << "[WARN] Failed to decrypt packet from"
                   << address.toString() << ":" << port << "-" << error;
        return false;
    }

    noteClientActivity(session);
    rememberActiveSession(address, port);

    quint8 ipVersion = 0;
    if (!plaintext.isEmpty()) {
        ipVersion = (static_cast<quint8>(plaintext[0]) >> 4) & 0x0F;
    }

    if (ipVersion != 4) {
        logSuppressedClientNonIpv4();
        return false;
    }

    qDebug() << "[DATA] Received IP packet from" << address.toString() << ":" << port
             << "size:" << plaintext.size() << "bytes, IP version:" << ipVersion;

    if (!m_tunDevice->isRunning()) {
        qDebug() << "[INFO] Linux TUN backend is not connected yet, packet accepted at protocol layer only";
        return true;
    }

    if (!m_tunDevice->sendPacket(plaintext)) {
        qWarning() << "[WARN] Failed to forward IPv4 packet into Linux TUN";
        return false;
    }

    qDebug() << "[OK] Forwarded IPv4 packet into Linux TUN";
    return true;
}

void VpnServer::handleKeepalive(const QHostAddress &address, quint16 port, const TunnelFrame &frame)
{
    Q_UNUSED(frame);
    ClientSession *session = findSession(address, port);
    if (!session || !session->established) {
        return;
    }

    noteClientActivity(session);
    rememberActiveSession(address, port);
}

void VpnServer::noteClientActivity(ClientSession *session)
{
    if (!session) {
        return;
    }

    session->lastActivityMs = QDateTime::currentMSecsSinceEpoch();
    session->disconnectLogged = false;
}

void VpnServer::rememberActiveSession(const QHostAddress &address, quint16 port)
{
    m_currentSessionKey = peerKey(address, port);
}

void VpnServer::onSessionMaintenance()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (m_suppressedClientNonIpv4Packets > 0 && now - m_lastClientNonIpv4LogMs >= 5000) {
        qDebug() << "[INFO] Suppressed" << m_suppressedClientNonIpv4Packets
                 << "non-IPv4 packets from client during the last 5 seconds. MVP currently supports IPv4 only";
        m_suppressedClientNonIpv4Packets = 0;
        m_lastClientNonIpv4LogMs = now;
    }

    if (m_suppressedTunNonIpv4Packets > 0 && now - m_lastTunNonIpv4LogMs >= 5000) {
        qDebug() << "[INFO] Suppressed" << m_suppressedTunNonIpv4Packets
                 << "non-IPv4 packets from Linux TUN during the last 5 seconds. MVP currently supports IPv4 only";
        m_suppressedTunNonIpv4Packets = 0;
        m_lastTunNonIpv4LogMs = now;
    }

    if (m_suppressedNoSessionPackets > 0 && now - m_lastNoSessionLogMs >= 5000) {
        qDebug() << "[INFO] Suppressed" << m_suppressedNoSessionPackets
                 << "packets from client without an active session during the last 5 seconds."
                 << "Client usually needs to re-run the handshake";
        m_suppressedNoSessionPackets = 0;
        m_lastNoSessionLogMs = now;
    }

    for (auto it = m_sessions.begin(); it != m_sessions.end();) {
        ClientSession &session = it.value();

        if (session.established) {
            if (now - session.lastActivityMs > kClientSessionIdleTimeoutMs) {
                qDebug() << "[STOP] Client" << session.address.toString() << ":" << session.port << "timed out";
                if (m_currentSessionKey == it.key()) {
                    m_currentSessionKey.clear();
                }
                it = m_sessions.erase(it);
                continue;
            }

            TunnelFrame keepalive;
            keepalive.type = TunnelPacketType::Keepalive;
            keepalive.sessionId = session.sessionId;
            keepalive.sequence = session.nextServerSequence++;
            sendFrame(session.address, session.port, keepalive);
        }

        ++it;
    }
}

void VpnServer::onTunPacketReceived(const QByteArray &packet)
{
    if (packet.isEmpty()) {
        return;
    }

    const quint8 ipVersion = (static_cast<quint8>(packet[0]) >> 4) & 0x0F;
    if (ipVersion != 4) {
        logSuppressedTunNonIpv4();
        return;
    }

    ClientSession *session = currentSession();
    if (!session) {
        qWarning() << "[WARN] No active client session to send a packet from Linux TUN";
        return;
    }

    TunnelFrame frame;
    frame.type = TunnelPacketType::Data;
    frame.flags = TunnelProtocol::kFlagEncrypted;
    frame.sessionId = session->sessionId;
    frame.sequence = session->nextServerSequence++;

    const QByteArray aad = TunnelProtocol::encodeHeader(frame, static_cast<quint16>(packet.size()));
    QString error;
    if (!TunnelCrypto::encryptPacket(session->keys.txKey,
                                     session->keys.txNoncePrefix,
                                     frame.sequence,
                                     aad,
                                     packet,
                                     &frame.payload,
                                     &frame.authTag,
                                     &error)) {
        qWarning() << "[WARN] Failed to encrypt packet from Linux TUN for client:" << error;
        return;
    }

    if (!sendFrame(session->address, session->port, frame)) {
        return;
    }

    qDebug() << "[DATA] Sent IPv4 packet from Linux TUN to client"
             << session->address.toString() << ":" << session->port
             << "size:" << packet.size() << "bytes";
}

void VpnServer::onTunError(const QString &error)
{
    qWarning() << "[WARN] Linux TUN backend error:" << error;
}

VpnServer::ClientSession *VpnServer::findSession(const QHostAddress &address, quint16 port)
{
    const QString key = peerKey(address, port);
    auto it = m_sessions.find(key);
    if (it == m_sessions.end()) {
        return nullptr;
    }
    return &it.value();
}

VpnServer::ClientSession *VpnServer::activeSession()
{
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
        if (it->established) {
            return &it.value();
        }
    }
    return nullptr;
}

VpnServer::ClientSession *VpnServer::currentSession()
{
    if (!m_currentSessionKey.isEmpty()) {
        auto it = m_sessions.find(m_currentSessionKey);
        if (it != m_sessions.end() && it->established) {
            return &it.value();
        }
    }

    return activeSession();
}

void VpnServer::logSuppressedClientNonIpv4()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_lastClientNonIpv4LogMs == 0 || now - m_lastClientNonIpv4LogMs >= 5000) {
        qDebug() << "[INFO] Client sent IPv6 or other non-IPv4 traffic."
                 << "MVP currently processes IPv4 only, so these packets are ignored";
        m_lastClientNonIpv4LogMs = now;
        m_suppressedClientNonIpv4Packets = 0;
        return;
    }

    ++m_suppressedClientNonIpv4Packets;
}

void VpnServer::logSuppressedTunNonIpv4()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_lastTunNonIpv4LogMs == 0 || now - m_lastTunNonIpv4LogMs >= 5000) {
        qDebug() << "[INFO] Linux TUN produced IPv6 or other non-IPv4 traffic."
                 << "MVP currently processes IPv4 only, so these packets are ignored";
        m_lastTunNonIpv4LogMs = now;
        m_suppressedTunNonIpv4Packets = 0;
        return;
    }

    ++m_suppressedTunNonIpv4Packets;
}

void VpnServer::logSuppressedPacketsWithoutSession(const QHostAddress &address, quint16 port)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_lastNoSessionLogMs == 0 || now - m_lastNoSessionLogMs >= 5000) {
        qDebug() << "[WARN] Client" << address.toString() << ":" << port
                 << "sent data without an active session. Server is waiting for a new handshake";
        m_lastNoSessionLogMs = now;
        m_suppressedNoSessionPackets = 0;
        return;
    }

    ++m_suppressedNoSessionPackets;
}
