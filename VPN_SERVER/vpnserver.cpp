#include "vpnserver.h"
#include <QDebug>
#include <QThread>
#include <QtEndian>

VpnServer::VpnServer(QObject *parent) : QObject(parent) {
    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &VpnServer::onNewConnection);
}

bool VpnServer::start(quint16 port) {
    if (!server->listen(QHostAddress::Any, port)) {
        qDebug() << "❌ Server error:" << server->errorString();
        return false;
    }
    qDebug() << "🌐 VPN Server listening on port" << port;
    return true;
}

void VpnServer::onNewConnection() {
    QTcpSocket *clientSocket = server->nextPendingConnection();
    qDebug() << "📡 Client connected from:" << clientSocket->peerAddress().toString();

    // Отправляем приветствие
    clientSocket->write("VPN_SERVER_READY");

    connect(clientSocket, &QTcpSocket::readyRead, this, [this, clientSocket]() {
        QByteArray data = clientSocket->readAll();

        // Проверяем, не приветствие ли это
        if (data == "VPN_CLIENT_INIT") {
            qDebug() << "   → VPN tunnel established";
            return;
        }

        // Обрабатываем пакет
        handlePacket(clientSocket, data);
    });

    connect(clientSocket, &QTcpSocket::disconnected, this, [this, clientSocket]() {
        qDebug() << "📡 Client disconnected";
        // Очищаем UDP соединения этого клиента
        for (auto it = udpConnections.begin(); it != udpConnections.end();) {
            if (it.value().clientSocket == clientSocket) {
                delete it.value().socket;
                it = udpConnections.erase(it);
            } else {
                ++it;
            }
        }
    });
}

void VpnServer::handlePacket(QTcpSocket* clientSocket, const QByteArray& packet) {
    qDebug() << "📨 Processing packet of size:" << packet.size() << "bytes";

    if (packet.size() < 20) {
        qDebug() << "   ⚠️ Packet too small:" << packet.size();
        return;
    }

    // Определяем версию IP
    unsigned char version = (packet[0] >> 4) & 0x0F;
    qDebug() << "   → IP version:" << (int)version;

    if (version != 4 && version != 6) {
        qDebug() << "   ⚠️ Unknown IP version:" << version << "- ignoring";
        return;
    }

    if (version == 4) {
        // IPv4
        unsigned char protocol = packet[9];

        qDebug() << "   → IPv4 packet, protocol:" << (int)protocol;

        if (protocol == 1) { // ICMP
            qDebug() << "   → Calling handleICMP...";
            handleICMP(clientSocket, packet);
        } else if (protocol == 6) { // TCP
            handleTCP(clientSocket, packet);
        } else if (protocol == 17) { // UDP
            handleUDP(clientSocket, packet);
        } else {
            qDebug() << "   ⚠️ Unsupported protocol:" << protocol;
        }
    } else if (version == 6) {
        qDebug() << "   → IPv6 packet";
        // Определяем протокол в IPv6 (следующий заголовок)
        if (packet.size() > 40) {
            unsigned char nextHeader = packet[6];

            if (nextHeader == 1 || nextHeader == 58 ) { // ICMPv6
                handleICMPv6(clientSocket, packet);
            } else if (nextHeader == 6) { // TCP
                handleTCP(clientSocket, packet);
            } else if (nextHeader == 17) { // UDP
                handleUDPv6(clientSocket, packet);
            } else {
                qDebug() << "   ⚠️ Unsupported IPv6 protocol:" << nextHeader;
            }
        }
    } else {
        qDebug() << "   ⚠️ Unknown IP version:" << version;
    }
}

void VpnServer::handleICMPv6(QTcpSocket* clientSocket, const QByteArray& packet) {
    qDebug() << "   → ICMPv6 packet (ignored for now)";
    // ICMPv6 нужно для IPv6邻居发现, пока игнорируем
}

void VpnServer::handleUDPv6(QTcpSocket* clientSocket, const QByteArray& packet) {
    qDebug() << "   → UDPv6 packet";
    // Для простоты - эхо
    clientSocket->write(packet);
}

void VpnServer::handleICMP(QTcpSocket* clientSocket, const QByteArray& packet) {
    if (packet.size() < 28) return;

    // Быстрое извлечение IP адресов
    quint32 sourceIP = ((quint32)(unsigned char)packet[12] << 24) |
                       ((quint32)(unsigned char)packet[13] << 16) |
                       ((quint32)(unsigned char)packet[14] << 8) |
                       ((quint32)(unsigned char)packet[15]);

    quint32 destIP = ((quint32)(unsigned char)packet[16] << 24) |
                     ((quint32)(unsigned char)packet[17] << 16) |
                     ((quint32)(unsigned char)packet[18] << 8) |
                     ((quint32)(unsigned char)packet[19]);

    // Проверяем тип ICMP
    unsigned char icmpType = packet[20];

    // Обрабатываем только Echo Request
    if (icmpType != 8) return;

    // Создаем ответный пакет (без копирования всего пакета)
    QByteArray response = packet;

    // Меняем IP адреса местами
    response[12] = packet[16];
    response[13] = packet[17];
    response[14] = packet[18];
    response[15] = packet[19];
    response[16] = packet[12];
    response[17] = packet[13];
    response[18] = packet[14];
    response[19] = packet[15];

    // Меняем тип ICMP на Echo Reply
    response[20] = 0;

    // Быстрый пересчет checksum
    response[22] = 0;
    response[23] = 0;

    quint32 sum = 0;
    const quint16* data = reinterpret_cast<const quint16*>(response.data() + 20);
    int size = response.size() - 20;
    for (int i = 0; i < size / 2; ++i) {
        sum += data[i];
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    if (size & 1) {
        sum += *reinterpret_cast<const quint8*>(response.data() + 20 + size - 1);
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    sum = ~sum & 0xFFFF;
    response[22] = (sum >> 8) & 0xFF;
    response[23] = sum & 0xFF;

    // НЕМЕДЛЕННАЯ отправка ответа
    clientSocket->write(response);
    clientSocket->flush(); // Принудительная отправка
}

void VpnServer::handleTCP(QTcpSocket* clientSocket, const QByteArray& packet) {
    qDebug() << "   → TCP packet (TCP forwarding not fully implemented yet)";
    // TODO: Реализовать TCP проксирование
    // Это сложнее, требует установки отдельного TCP соединения
    clientSocket->write(packet); // Пока просто эхо
}

void VpnServer::handleUDP(QTcpSocket* clientSocket, const QByteArray& packet) {
    if (packet.size() < 28) return; // IP заголовок (20) + UDP заголовок (8)

    quint32 destIP = extractDestIP(packet);
    quint16 destPort = extractDestPort(packet);

    QHostAddress destAddr(destIP);

    qDebug() << "   → UDP packet to:" << destAddr.toString() << ":" << destPort;

    // ========== DNS ФОРВАРДЕР ==========
    // Перенаправляем все DNS запросы (порт 53) на Google DNS
    bool isDNSRequest = (destPort == 53);

    if (isDNSRequest) {
        qDebug() << "      → DNS request detected!";
        // Перенаправляем на Google Public DNS
        destAddr = QHostAddress("8.8.8.8");
        destPort = 53;
        qDebug() << "      → Redirecting to Google DNS: 8.8.8.8:53";
    }
    // ==================================

    // Извлекаем UDP данные (после IP и UDP заголовков)
    int ipHeaderLen = (packet[0] & 0x0F) * 4;
    int udpDataOffset = ipHeaderLen + 8; // IP header + UDP header

    if (packet.size() <= udpDataOffset) return;

    QByteArray udpData = packet.mid(udpDataOffset);

    // Для DNS запросов можно вывести информацию
    if (isDNSRequest && udpData.size() > 12) {
        // Извлекаем доменное имя из DNS запроса (упрощённо)
        int pos = 12; // Пропускаем DNS заголовок
        if (udpData.size() > pos) {
            QString domain;
            while (pos < udpData.size()) {
                unsigned char len = udpData[pos];
                if (len == 0) break;
                pos++;
                if (pos + len <= udpData.size()) {
                    domain += QString::fromLatin1(udpData.mid(pos, len)) + ".";
                    pos += len;
                } else {
                    break;
                }
            }
            if (!domain.isEmpty()) {
                qDebug() << "      → DNS query for:" << domain;
            }
        }
    }

    // Создаем уникальный ID для соединения (учитываем перенаправление)
    quint64 connId = getConnectionId(destAddr, destPort);
    // Добавляем ID клиента в connId, чтобы разные клиенты не мешали друг другу
    quint64 clientId = (quint64)clientSocket;
    quint64 fullConnId = connId ^ clientId; // XOR для уникальности

    if (!udpConnections.contains(fullConnId)) {
        UDPConnection conn;
        conn.socket = new QUdpSocket(this);
        conn.clientSocket = clientSocket;
        conn.targetAddress = destAddr;
        conn.targetPort = destPort;

        // Сохраняем оригинальный адрес для DNS (для логов)
        if (isDNSRequest) {
            qDebug() << "      → Created DNS forwarder socket";
        }

        // Подключаем сигнал готовности к чтению
        connect(conn.socket, &QUdpSocket::readyRead, this, [this, clientSocket, fullConnId, isDNSRequest]() {
            if (!udpConnections.contains(fullConnId)) return;

            UDPConnection& conn = udpConnections[fullConnId];
            while (conn.socket->hasPendingDatagrams()) {
                QByteArray responseData;
                responseData.resize(conn.socket->pendingDatagramSize());
                QHostAddress senderAddr;
                quint16 senderPort;

                conn.socket->readDatagram(responseData.data(), responseData.size(),
                                          &senderAddr, &senderPort);

                if (isDNSRequest) {
                    qDebug() << "      ← DNS response from:" << senderAddr.toString() << ":" << senderPort
                             << "(size:" << responseData.size() << "bytes)";
                } else {
                    qDebug() << "      ← UDP response from:" << senderAddr.toString() << ":" << senderPort;
                }

                // Отправляем ответ обратно клиенту
                clientSocket->write(responseData);
            }
        });

        udpConnections[fullConnId] = conn;

        if (!isDNSRequest) {
            qDebug() << "      → Created new UDP socket for" << destAddr.toString() << ":" << destPort;
        }
    }

    // Отправляем UDP датаграмму
    UDPConnection& conn = udpConnections[fullConnId];
    conn.socket->writeDatagram(udpData, conn.targetAddress, conn.targetPort);

    if (isDNSRequest) {
        qDebug() << "      → DNS query forwarded to" << conn.targetAddress.toString() << ":" << conn.targetPort
                 << "(" << udpData.size() << "bytes)";
    } else {
        qDebug() << "      → UDP datagram sent (" << udpData.size() << "bytes)";
    }
}

quint32 VpnServer::extractDestIP(const QByteArray& packet) {
    if (packet.size() < 24) return 0;
    // IP заголовок: байты 16-19 - destination IP
    return ((quint32)(unsigned char)packet[16] << 24) |
           ((quint32)(unsigned char)packet[17] << 16) |
           ((quint32)(unsigned char)packet[18] << 8) |
           ((quint32)(unsigned char)packet[19]);
}

quint16 VpnServer::extractDestPort(const QByteArray& packet) {
    if (packet.size() < 22) return 0;
    int ipHeaderLen = (packet[0] & 0x0F) * 4;
    if (packet.size() < ipHeaderLen + 2) return 0;
    // UDP/TCP заголовок: байты 2-3 - destination port
    return ((quint16)(unsigned char)packet[ipHeaderLen + 2] << 8) |
           ((quint16)(unsigned char)packet[ipHeaderLen + 3]);
}

quint64 VpnServer::getConnectionId(const QHostAddress& addr, quint16 port) {
    return ((quint64)addr.toIPv4Address() << 32) | port;
}
