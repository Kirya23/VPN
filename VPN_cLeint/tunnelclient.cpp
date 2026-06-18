#include "tunnelclient.h"

#include <QAbstractSocket>
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

TunnelClient::TunnelClient(QObject *parent)
    : QObject(parent)
    , m_socket(new QUdpSocket(this))
    , m_serverPort(0)
    , m_sessionId(0)
    , m_nextSequence(1)
    , m_udpResetNoticeShown(false)
    , m_running(false)
{
    connect(m_socket, &QUdpSocket::readyRead, this, &TunnelClient::onReadyRead);
    connect(m_socket, &QUdpSocket::errorOccurred, this, &TunnelClient::onSocketError);
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
    m_nextSequence = 1;
    m_udpResetNoticeShown = false;
    m_running = true;

    if (!sendControlPacket(TunnelPacketType::ClientHello, QByteArrayLiteral("qt-vpn-mvp"))) {
        stop();
        return false;
    }

    qDebug() << "✅ Туннельный транспорт по UDP готов ->" << m_serverAddress.toString() << ":" << m_serverPort;
    emit started();
    return true;
}

void TunnelClient::stop() {
    if (!m_running) {
        return;
    }

    m_running = false;
    m_udpResetNoticeShown = false;
    m_socket->close();
    emit stopped();
}

bool TunnelClient::sendIpPacket(const QByteArray &packet) {
    TunnelFrame frame;
    frame.type = TunnelPacketType::Data;
    frame.sessionId = m_sessionId;
    frame.sequence = m_nextSequence++;
    frame.payload = packet;
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
            qDebug() << "⚠️ Игнорируем датаграмму от неожиданного узла" << senderAddress.toString() << ":" << senderPort;
            continue;
        }

        TunnelFrame frame;
        QString error;
        if (!TunnelProtocol::decodeFrame(datagram, &frame, &error)) {
            emit errorOccurred(QStringLiteral("Не удалось разобрать туннельную датаграмму: %1").arg(error));
            continue;
        }

        m_udpResetNoticeShown = false;

        if (frame.type == TunnelPacketType::Data) {
            emit ipPacketReceived(frame.payload);
        } else {
            emit controlFrameReceived(frame);
        }
    }
}

void TunnelClient::onSocketError(QAbstractSocket::SocketError socketError) {
#ifdef Q_OS_WIN
    if (socketError == QAbstractSocket::ConnectionRefusedError) {
        if (!m_udpResetNoticeShown) {
            qDebug() << "ℹ️ UDP-сервер пока не отвечает на" << m_serverAddress.toString() << ":" << m_serverPort;
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
        qDebug() << "⚠️ Не удалось получить нативный дескриптор UDP-сокета для настройки Windows";
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
        qDebug() << "⚠️ Не удалось отключить UDP ConnReset в Windows, код:" << WSAGetLastError();
    }
#endif
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
