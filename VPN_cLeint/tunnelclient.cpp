#include "tunnelclient.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QDebug>
#include <QHostInfo>
#include <QUdpSocket>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <mstcpip.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#endif

namespace {
constexpr int kKeepaliveIntervalMs = 5000;
constexpr qint64 kServerSilenceTimeoutMs = 60000;
}

TunnelClient::TunnelClient(QObject *parent)
    : QObject(parent)
    , m_socket(new QUdpSocket(this))
    , m_serverPort(0)
    , m_sessionId(0)
    , m_nextSequence(1)
    , m_keepaliveTimer(new QTimer(this))
    , m_connectionMonitorTimer(new QTimer(this))
    , m_lastServerActivityMs(0)
    , m_connectionAlive(false)
    , m_udpResetNoticeShown(false)
    , m_running(false)
    , m_state(TunnelClientState::Stopped)
{
    connect(m_socket, &QUdpSocket::readyRead, this, &TunnelClient::onReadyRead);
    connect(m_socket, &QUdpSocket::errorOccurred, this, &TunnelClient::onSocketError);

    m_keepaliveTimer->setInterval(kKeepaliveIntervalMs);
    connect(m_keepaliveTimer, &QTimer::timeout, this, &TunnelClient::onKeepaliveTimer);

    m_connectionMonitorTimer->setInterval(1000);
    connect(m_connectionMonitorTimer, &QTimer::timeout, this, &TunnelClient::onConnectionMonitorTimer);
}

bool TunnelClient::start(const QString &serverAddress, quint16 serverPort) {
    if (m_running) {
        return true;
    }

    if (!resolveServerAddress(serverAddress)) {
        emit errorOccurred(QStringLiteral("Не удалось определить адрес сервера: %1").arg(serverAddress));
        return false;
    }

    if (!m_socket->bind(QHostAddress::AnyIPv4, 0)) {
        emit errorOccurred(QStringLiteral("Не удалось привязать UDP-сокет: %1").arg(m_socket->errorString()));
        return false;
    }

    configurePlatformSocketOptions();

    m_serverPort = serverPort;
    m_sessionId = 0;
    m_nextSequence = 1;
    m_lastServerActivityMs = QDateTime::currentMSecsSinceEpoch();
    m_connectionAlive = false;
    m_udpResetNoticeShown = false;
    m_running = true;
    m_state = TunnelClientState::Handshake;
    m_connectionMonitorTimer->start();

    if (!beginHandshake()) {
        stop();
        return false;
    }

    qDebug() << "[OK] Туннельный транспорт по UDP готов ->" << m_serverAddress.toString() << ":" << m_serverPort;
    qDebug() << "[WAIT] Ожидаем завершения handshake с сервером...";
    emit started();
    return true;
}

void TunnelClient::stop() {
    if (!m_running) {
        return;
    }

    m_running = false;
    m_state = TunnelClientState::Stopped;
    m_sessionId = 0;
    m_nextSequence = 1;
    m_clientPublicKey.clear();
    m_clientPrivateKey.clear();
    m_clientRandom.clear();
    m_sessionKeys = TunnelSessionKeys();
    m_keepaliveTimer->stop();
    m_connectionMonitorTimer->stop();
    m_lastServerActivityMs = 0;
    m_connectionAlive = false;
    m_udpResetNoticeShown = false;
    m_socket->close();
    emit stopped();
}

bool TunnelClient::sendIpPacket(const QByteArray &packet) {
    if (m_state != TunnelClientState::Established) {
        emit errorOccurred(QStringLiteral("Нельзя отправить IP-пакет: handshake ещё не завершён"));
        return false;
    }

    TunnelFrame frame;
    frame.type = TunnelPacketType::Data;
    frame.flags = TunnelProtocol::kFlagEncrypted;
    frame.sessionId = m_sessionId;
    frame.sequence = m_nextSequence++;
    const QByteArray aad = TunnelProtocol::encodeHeader(frame, static_cast<quint16>(packet.size()));

    QString error;
    if (!TunnelCrypto::encryptPacket(m_sessionKeys.txKey,
                                     m_sessionKeys.txNoncePrefix,
                                     frame.sequence,
                                     aad,
                                     packet,
                                     &frame.payload,
                                     &frame.authTag,
                                     &error)) {
        emit errorOccurred(QStringLiteral("Не удалось зашифровать IP-пакет: %1").arg(error));
        return false;
    }

    return sendFrame(frame);
}

bool TunnelClient::sendControlPacket(TunnelPacketType type, const QByteArray &payload) {
    TunnelFrame frame;
    frame.type = type;
    frame.sessionId = m_sessionId;
    frame.sequence = m_nextSequence++;
    frame.payload = payload;
    return sendFrame(frame);
}

void TunnelClient::onReadyRead() {
    while (m_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(static_cast<int>(m_socket->pendingDatagramSize()));

        QHostAddress senderAddress;
        quint16 senderPort = 0;
        if (m_socket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort) < 0) {
#ifdef Q_OS_WIN
            if (m_socket->error() == QAbstractSocket::ConnectionRefusedError) {
                continue;
            }
#endif
            emit errorOccurred(QStringLiteral("Не удалось прочитать UDP-датаграмму: %1").arg(m_socket->errorString()));
            continue;
        }

        if (senderAddress != m_serverAddress || senderPort != m_serverPort) {
            qDebug() << "[WARN] Игнорируем датаграмму от неожиданного узла" << senderAddress.toString() << ":" << senderPort;
            continue;
        }

        TunnelFrame frame;
        QString error;
        if (!TunnelProtocol::decodeFrame(datagram, &frame, &error)) {
            emit errorOccurred(QStringLiteral("Не удалось разобрать туннельную датаграмму: %1").arg(error));
            continue;
        }

        noteServerActivity();
        m_udpResetNoticeShown = false;

        if (frame.type == TunnelPacketType::Data) {
            if (m_state != TunnelClientState::Established) {
                emit errorOccurred(QStringLiteral("Получен пакет данных до завершения handshake"));
                continue;
            }

            if ((frame.flags & TunnelProtocol::kFlagEncrypted) == 0) {
                emit errorOccurred(QStringLiteral("Получен незашифрованный пакет данных от сервера"));
                continue;
            }

            const QByteArray aad = TunnelProtocol::encodeHeader(frame, static_cast<quint16>(frame.payload.size()));
            QByteArray plaintext;
            if (!TunnelCrypto::decryptPacket(m_sessionKeys.rxKey,
                                             m_sessionKeys.rxNoncePrefix,
                                             frame.sequence,
                                             aad,
                                             frame.payload,
                                             frame.authTag,
                                             &plaintext,
                                             &error)) {
                emit errorOccurred(QStringLiteral("Не удалось расшифровать пакет от сервера: %1").arg(error));
                continue;
            }

            emit ipPacketReceived(plaintext);
        } else {
            if (frame.type == TunnelPacketType::ServerHello && m_state == TunnelClientState::Handshake) {
                if (!finishHandshake(frame)) {
                    continue;
                }
            }

            if (frame.type != TunnelPacketType::Keepalive) {
                emit controlFrameReceived(frame);
            }
        }
    }
}

void TunnelClient::onSocketError(QAbstractSocket::SocketError socketError) {
#ifdef Q_OS_WIN
    if (socketError == QAbstractSocket::ConnectionRefusedError) {
        if (!m_udpResetNoticeShown) {
            qDebug() << "[INFO] UDP-сервер пока не отвечает на" << m_serverAddress.toString() << ":" << m_serverPort;
            m_udpResetNoticeShown = true;
        }
        return;
    }
#endif

    emit errorOccurred(QStringLiteral("Ошибка UDP-сокета: %1").arg(m_socket->errorString()));
}

void TunnelClient::configurePlatformSocketOptions() {
#ifdef Q_OS_WIN
    const SOCKET nativeSocket = static_cast<SOCKET>(m_socket->socketDescriptor());
    if (nativeSocket == INVALID_SOCKET) {
        qDebug() << "[WARN] Не удалось получить нативный дескриптор UDP-сокета для настройки Windows";
        return;
    }

    DWORD bytesReturned = 0;
    BOOL disableUdpReset = FALSE;
    const int result = WSAIoctl(nativeSocket,
                                SIO_UDP_CONNRESET,
                                &disableUdpReset,
                                sizeof(disableUdpReset),
                                nullptr,
                                0,
                                &bytesReturned,
                                nullptr,
                                nullptr);
    if (result != 0) {
        qDebug() << "[WARN] Не удалось отключить UDP ConnReset в Windows, код:" << WSAGetLastError();
    }
#endif
}

void TunnelClient::noteServerActivity() {
    m_lastServerActivityMs = QDateTime::currentMSecsSinceEpoch();
    if (!m_connectionAlive && m_state == TunnelClientState::Established) {
        m_connectionAlive = true;
        emit connectionRestored();
    }
}

bool TunnelClient::resolveServerAddress(const QString &serverAddress) {
    const QHostAddress directAddress(serverAddress);
    if (!directAddress.isNull()) {
        m_serverAddress = directAddress;
        return true;
    }

    const QHostInfo hostInfo = QHostInfo::fromName(serverAddress);
    if (hostInfo.error() != QHostInfo::NoError) {
        return false;
    }

    for (const QHostAddress &address : hostInfo.addresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            m_serverAddress = address;
            return true;
        }
    }

    return false;
}

bool TunnelClient::beginHandshake() {
    QString error;
    if (!TunnelCrypto::generateX25519KeyPair(&m_clientPublicKey, &m_clientPrivateKey, &error)) {
        emit errorOccurred(QStringLiteral("Не удалось сгенерировать клиентскую ключевую пару: %1").arg(error));
        return false;
    }

    if (!TunnelCrypto::randomBytes(TunnelCrypto::kRandomSize, &m_clientRandom, &error)) {
        emit errorOccurred(QStringLiteral("Не удалось сгенерировать клиентскую случайную последовательность: %1").arg(error));
        return false;
    }

    ClientHelloPayload hello;
    hello.publicKey = m_clientPublicKey;
    hello.random = m_clientRandom;

    return sendControlPacket(TunnelPacketType::ClientHello, HandshakeProtocol::encodeClientHello(hello));
}

bool TunnelClient::finishHandshake(const TunnelFrame &frame) {
    ServerHelloPayload serverHello;
    QString error;
    if (!HandshakeProtocol::decodeServerHello(frame.payload, &serverHello, &error)) {
        emit errorOccurred(QStringLiteral("Не удалось разобрать ServerHello: %1").arg(error));
        return false;
    }

    if (frame.sessionId == 0) {
        emit errorOccurred(QStringLiteral("Сервер вернул некорректный session id"));
        return false;
    }

    TunnelSessionKeys derivedKeys;
    if (!TunnelCrypto::deriveClientSessionKeys(m_clientPrivateKey,
                                               m_clientPublicKey,
                                               m_clientRandom,
                                               serverHello.publicKey,
                                               serverHello.random,
                                               &derivedKeys,
                                               &error)) {
        emit errorOccurred(QStringLiteral("Не удалось вывести сессионные ключи: %1").arg(error));
        return false;
    }

    m_sessionId = frame.sessionId;
    m_sessionKeys = derivedKeys;
    m_state = TunnelClientState::Established;
    m_connectionAlive = true;
    m_keepaliveTimer->start();

    qDebug() << "[OK] Handshake завершён, session id:" << m_sessionId;
    emit sessionEstablished();
    return true;
}

void TunnelClient::onKeepaliveTimer() {
    if (!m_running || m_state != TunnelClientState::Established) {
        return;
    }

    sendControlPacket(TunnelPacketType::Keepalive);
}

void TunnelClient::onConnectionMonitorTimer() {
    if (!m_running || m_state != TunnelClientState::Established || !m_connectionAlive) {
        return;
    }

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - m_lastServerActivityMs > kServerSilenceTimeoutMs) {
        m_connectionAlive = false;
        emit connectionLost();
    }
}

bool TunnelClient::sendFrame(const TunnelFrame &frame) {
    if (!m_running) {
        emit errorOccurred(QStringLiteral("Туннельный клиент не запущен"));
        return false;
    }

    const QByteArray datagram = TunnelProtocol::encodeFrame(frame);
    const qint64 bytesSent = m_socket->writeDatagram(datagram, m_serverAddress, m_serverPort);
    if (bytesSent != datagram.size()) {
        emit errorOccurred(QStringLiteral("Не удалось отправить UDP-датаграмму: %1").arg(m_socket->errorString()));
        return false;
    }

    return true;
}
