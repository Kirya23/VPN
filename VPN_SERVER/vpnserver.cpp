#include "vpnserver.h"

#include <QDebug>
#include <QtEndian>

VpnServer::VpnServer(QObject *parent)
    : QObject(parent)
    , m_socket(new QUdpSocket(this))
    , m_tunDevice(new LinuxTunDevice(this))
{
    connect(m_socket, &QUdpSocket::readyRead, this, &VpnServer::onReadyRead);
    connect(m_tunDevice, &LinuxTunDevice::packetReceived, this, &VpnServer::onTunPacketReceived);
    connect(m_tunDevice, &LinuxTunDevice::errorOccurred, this, &VpnServer::onTunError);
}

bool VpnServer::start(quint16 port) {
    if (!m_socket->bind(QHostAddress::AnyIPv4, port)) {
        qDebug() << "❌ Ошибка запуска UDP-сервера:" << m_socket->errorString();
        return false;
    }
    qDebug() << "🌐 VPN-сервер слушает UDP-порт" << port;

    if (m_tunDevice->initialize(QStringLiteral("qvpn0"), QStringLiteral("10.10.0.1/24"))) {
        if (!m_tunDevice->start()) {
            qDebug() << "⚠️ Linux TUN backend не запущен, сервер пока останется только в режиме протокола";
        }
    } else {
        qDebug() << "ℹ️ Linux TUN backend пока недоступен в этой сборке или окружении";
    }

    return true;
}

void VpnServer::onReadyRead() {
    while (m_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(static_cast<int>(m_socket->pendingDatagramSize()));

        QHostAddress senderAddress;
        quint16 senderPort = 0;
        if (m_socket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort) < 0) {
            qDebug() << "❌ Не удалось прочитать UDP-датаграмму:" << m_socket->errorString();
            continue;
        }

        TunnelFrame frame;
        QString error;
        if (!TunnelProtocol::decodeFrame(datagram, &frame, &error)) {
            qDebug() << "❌ Не удалось разобрать туннельную датаграмму от"
                     << senderAddress.toString() << ":" << senderPort << "-" << error;
            continue;
        }

        if (frame.type == TunnelPacketType::ClientHello) {
            processClientHello(senderAddress, senderPort, frame);
            continue;
        }

        if (frame.type == TunnelPacketType::Data) {
            processEncryptedData(senderAddress, senderPort, frame);
            continue;
        }

        qDebug() << "ℹ️ Получен управляющий кадр от" << senderAddress.toString() << ":" << senderPort
                 << "тип:" << static_cast<int>(frame.type);
    }
}

QString VpnServer::peerKey(const QHostAddress &address, quint16 port) const {
    return QStringLiteral("%1:%2").arg(address.toString()).arg(port);
}

bool VpnServer::sendFrame(const QHostAddress &address, quint16 port, const TunnelFrame &frame) {
    const QByteArray datagram = TunnelProtocol::encodeFrame(frame);
    const qint64 bytesSent = m_socket->writeDatagram(datagram, address, port);
    if (bytesSent != datagram.size()) {
        qDebug() << "❌ Не удалось отправить UDP-датаграмму клиенту"
                 << address.toString() << ":" << port << "-" << m_socket->errorString();
        return false;
    }
    return true;
}

bool VpnServer::processClientHello(const QHostAddress &address, quint16 port, const TunnelFrame &frame) {
    ClientHelloPayload clientHello;
    QString error;
    if (!HandshakeProtocol::decodeClientHello(frame.payload, &clientHello, &error)) {
        qDebug() << "❌ Некорректный ClientHello от" << address.toString() << ":" << port << "-" << error;
        return false;
    }

    ClientSession session;
    session.address = address;
    session.port = port;
    session.clientPublicKey = clientHello.publicKey;
    session.clientRandom = clientHello.random;

    if (!TunnelCrypto::generateX25519KeyPair(&session.serverPublicKey, &session.serverPrivateKey, &error)) {
        qDebug() << "❌ Не удалось сгенерировать серверную ключевую пару:" << error;
        return false;
    }

    if (!TunnelCrypto::randomBytes(TunnelCrypto::kRandomSize, &session.serverRandom, &error)) {
        qDebug() << "❌ Не удалось сгенерировать серверную случайную последовательность:" << error;
        return false;
    }

    QByteArray sessionIdBytes;
    if (!TunnelCrypto::randomBytes(sizeof(quint32), &sessionIdBytes, &error)) {
        qDebug() << "❌ Не удалось сгенерировать session id:" << error;
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
        qDebug() << "❌ Не удалось вывести серверные сессионные ключи:" << error;
        return false;
    }

    session.established = true;
    m_sessions.insert(peerKey(address, port), session);

    ServerHelloPayload serverHello;
    serverHello.publicKey = session.serverPublicKey;
    serverHello.random = session.serverRandom;

    TunnelFrame response;
    response.type = TunnelPacketType::ServerHello;
    response.sessionId = session.sessionId;
    response.sequence = 1;
    response.payload = HandshakeProtocol::encodeServerHello(serverHello);

    qDebug() << "🤝 Handshake с клиентом" << address.toString() << ":" << port
             << "завершён, session id:" << session.sessionId;

    return sendFrame(address, port, response);
}

bool VpnServer::processEncryptedData(const QHostAddress &address, quint16 port, const TunnelFrame &frame) {
    ClientSession *session = findSession(address, port);
    if (!session || !session->established) {
        qDebug() << "⚠️ Получен пакет данных от клиента без активной сессии"
                 << address.toString() << ":" << port;
        return false;
    }

    if (frame.sessionId != session->sessionId) {
        qDebug() << "⚠️ Некорректный session id от клиента"
                 << address.toString() << ":" << port
                 << "ожидался:" << session->sessionId << "получен:" << frame.sessionId;
        return false;
    }

    if ((frame.flags & TunnelProtocol::kFlagEncrypted) == 0) {
        qDebug() << "⚠️ Получен незашифрованный пакет данных от клиента"
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
        qDebug() << "❌ Не удалось расшифровать пакет от клиента"
                 << address.toString() << ":" << port << "-" << error;
        return false;
    }

    quint8 ipVersion = 0;
    if (!plaintext.isEmpty()) {
        ipVersion = (static_cast<quint8>(plaintext[0]) >> 4) & 0x0F;
    }

    if (ipVersion != 4) {
        qDebug() << "ℹ️ IPv6 или неизвестный IP-пакет временно пропущен. Текущий MVP сфокусирован на IPv4-only";
        return false;
    }

    qDebug() << "📥 Получен IP-пакет от клиента" << address.toString() << ":" << port
             << "размер:" << plaintext.size() << "байт, версия IP:" << ipVersion;

    if (!m_tunDevice->isRunning()) {
        qDebug() << "   → Linux TUN backend ещё не подключён, пакет принят только на уровне протокола";
        return true;
    }

    if (!m_tunDevice->sendPacket(plaintext)) {
        qDebug() << "⚠️ Не удалось передать IPv4-пакет в Linux TUN";
        return false;
    }

    qDebug() << "   → IPv4-пакет передан в Linux TUN";

    return true;
}

void VpnServer::onTunPacketReceived(const QByteArray &packet) {
    if (packet.isEmpty()) {
        return;
    }

    const quint8 ipVersion = (static_cast<quint8>(packet[0]) >> 4) & 0x0F;
    if (ipVersion != 4) {
        qDebug() << "ℹ️ Пакет из Linux TUN не является IPv4, временно пропускаем";
        return;
    }

    ClientSession *session = activeSession();
    if (!session) {
        qDebug() << "⚠️ Нет активной клиентской сессии для отправки пакета из Linux TUN";
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
        qDebug() << "❌ Не удалось зашифровать пакет из Linux TUN для клиента:" << error;
        return;
    }

    if (!sendFrame(session->address, session->port, frame)) {
        return;
    }

    qDebug() << "📤 IPv4-пакет из Linux TUN отправлен клиенту"
             << session->address.toString() << ":" << session->port
             << "размер:" << packet.size() << "байт";
}

void VpnServer::onTunError(const QString &error) {
    qDebug() << "❌ Ошибка Linux TUN backend:" << error;
}

VpnServer::ClientSession *VpnServer::findSession(const QHostAddress &address, quint16 port) {
    const QString key = peerKey(address, port);
    auto it = m_sessions.find(key);
    if (it == m_sessions.end()) {
        return nullptr;
    }
    return &it.value();
}

VpnServer::ClientSession *VpnServer::activeSession() {
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
        if (it->established) {
            return &it.value();
        }
    }
    return nullptr;
}
