#include "wintunadapter.h"
#include <QDebug>
#include <QThread>

// GUID для адаптера (можно сгенерировать свой через guidgen)
// Использование фиксированного GUID помогает сохранять настройки сети
static const GUID MY_VPN_GUID = {0x12345678, 0x1234, 0x1234,
                                 {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34}};

WintunAdapter::WintunAdapter(QObject *parent)
    : QObject(parent)
    , m_wintunDll(nullptr)
    , m_adapter(nullptr)
    , m_session(nullptr)
    , m_readThread(nullptr)
    , m_stopEvent(nullptr)
    , m_running(false)
    , pWintunCreateAdapter(nullptr)
    , pWintunCloseAdapter(nullptr)
    , pWintunStartSession(nullptr)
    , pWintunEndSession(nullptr)
    , pWintunAllocateSendPacket(nullptr)
    , pWintunSendPacket(nullptr)
    , pWintunReceivePacket(nullptr)
    , pWintunReleaseReceivePacket(nullptr)
    , pWintunGetReadWaitEvent(nullptr)
    , pWintunGetRunningDriverVersion(nullptr)
{
}

WintunAdapter::~WintunAdapter() {
    stop();
    unloadWintunLibrary();
}

bool WintunAdapter::initialize(const QString &adapterName) {
    m_adapterName = adapterName;

    // Загружаем Wintun DLL
    if (!loadWintunLibrary()) {
        emit errorOccurred("Failed to load wintun.dll");
        return false;
    }

    // Проверяем версию драйвера
    DWORD version = pWintunGetRunningDriverVersion();
    if (version == 0) {
        emit errorOccurred("Wintun driver not loaded or error getting version");
        return false;
    }
    qDebug() << "Wintun driver version:" << version;

    // Создаем адаптер (или открываем существующий)
    std::wstring wideName = m_adapterName.toStdWString();
    m_adapter = pWintunCreateAdapter(wideName.c_str(), L"Wintun", &MY_VPN_GUID);

    if (!m_adapter) {
        // Если не удалось создать, возможно адаптер уже существует - пробуем открыть
        m_adapter = pWintunOpenAdapter(wideName.c_str());
        if (!m_adapter) {
            emit errorOccurred("Failed to create or open Wintun adapter");
            return false;
        }
        qDebug() << "Opened existing adapter:" << m_adapterName;
    } else {
        qDebug() << "Created new adapter:" << m_adapterName;
    }

    return true;
}

bool WintunAdapter::start() {
    if (m_running) return true;

    // Запускаем сессию с кольцевым буфером (емкость 2 МБ - хороший выбор)
    const DWORD ringCapacity = 0x200000; // 2 MiB
    m_session = pWintunStartSession(m_adapter, ringCapacity);

    if (!m_session) {
        emit errorOccurred("Failed to start Wintun session");
        return false;
    }

    qDebug() << "Wintun session started with ring capacity:" << ringCapacity;

    // Создаем событие для остановки потока чтения
    m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!m_stopEvent) {
        pWintunEndSession(m_session);
        m_session = nullptr;
        emit errorOccurred("Failed to create stop event");
        return false;
    }

    m_running = true;

    // Запускаем поток для чтения пакетов
    m_readThread = CreateThread(nullptr, 0,
                                [](LPVOID param) -> DWORD {
                                    reinterpret_cast<WintunAdapter*>(param)->readerThreadFunction();
                                    return 0;
                                },
                                this, 0, nullptr);

    if (!m_readThread) {
        m_running = false;
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
        pWintunEndSession(m_session);
        m_session = nullptr;
        emit errorOccurred("Failed to create reader thread");
        return false;
    }

    emit adapterReady();
    qDebug() << "Wintun adapter is running and ready to capture traffic";

    return true;
}

void WintunAdapter::stop() {
    if (!m_running) return;

    m_running = false;

    // Сигнализируем потоку остановиться
    if (m_stopEvent) {
        SetEvent(m_stopEvent);
    }

    // Ждем завершения потока чтения
    if (m_readThread) {
        WaitForSingleObject(m_readThread, 5000);
        CloseHandle(m_readThread);
        m_readThread = nullptr;
    }

    // Завершаем сессию
    if (m_session) {
        pWintunEndSession(m_session);
        m_session = nullptr;
    }

    // Закрываем событие
    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }

    // Закрываем адаптер (это удалит его из системы)
    if (m_adapter) {
        pWintunCloseAdapter(m_adapter);
        m_adapter = nullptr;
    }

    qDebug() << "Wintun adapter stopped";
}

bool WintunAdapter::sendPacket(const QByteArray &packet) {
    if (!m_running || !m_session) return false;

    // Выделяем буфер для отправки пакета
    BYTE *outPacket = pWintunAllocateSendPacket(m_session, packet.size());
    if (!outPacket) {
        // ERROR_BUFFER_OVERFLOW означает, что кольцевой буфер заполнен - пакет дропаем[citation:2]
        if (GetLastError() != ERROR_BUFFER_OVERFLOW) {
            qDebug() << "Failed to allocate send packet, error:" << GetLastError();
        }
        return false;
    }

    // Копируем данные в буфер Wintun
    memcpy(outPacket, packet.data(), packet.size());

    // Отправляем пакет
    pWintunSendPacket(m_session, outPacket);

    return true;
}

QByteArray WintunAdapter::receivePacket() {
    if (!m_running || !m_session) return QByteArray();

    DWORD packetSize;
    BYTE *packet = pWintunReceivePacket(m_session, &packetSize);

    if (packet && packetSize > 0) {
        QByteArray data(reinterpret_cast<char*>(packet), packetSize);
        pWintunReleaseReceivePacket(m_session, packet);
        return data;
    }

    return QByteArray();
}

void WintunAdapter::readerThreadFunction() {
    qDebug() << "Wintun reader thread started";

    while (m_running) {
        // Ждем появления пакетов или сигнала остановки[citation:2][citation:3]
        HANDLE waitHandles[2] = { m_stopEvent, pWintunGetReadWaitEvent(m_session) };
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        // Если остановили - выходим
        if (waitResult == WAIT_OBJECT_0) {
            break;
        }

        // Читаем все доступные пакеты
        while (m_running) {
            QByteArray packet = receivePacket();
            if (packet.isEmpty()) {
                break; // Нет больше пакетов
            }

            // Отправляем пакет в главный поток через сигнал
            emit packetReceived(packet);
        }
    }

    qDebug() << "Wintun reader thread stopped";
}

bool WintunAdapter::loadWintunLibrary() {
    // Пробуем загрузить wintun.dll из той же директории
    m_wintunDll = LoadLibraryW(L"wintun.dll");
    if (!m_wintunDll) {
        qDebug() << "Failed to load wintun.dll, error:" << GetLastError();
        return false;
    }

// Загружаем все необходимые функции
#define LOAD_FUNC(name) \
    p##name = (name##_t)GetProcAddress(m_wintunDll, #name); \
        if (!p##name) { \
            qDebug() << "Failed to load function:" #name; \
            return false; \
    }

    LOAD_FUNC(WintunCreateAdapter);
    LOAD_FUNC(WintunCloseAdapter);
    LOAD_FUNC(WintunStartSession);
    LOAD_FUNC(WintunEndSession);
    LOAD_FUNC(WintunAllocateSendPacket);
    LOAD_FUNC(WintunSendPacket);
    LOAD_FUNC(WintunReceivePacket);
    LOAD_FUNC(WintunReleaseReceivePacket);
    LOAD_FUNC(WintunGetReadWaitEvent);
    LOAD_FUNC(WintunGetRunningDriverVersion);

#undef LOAD_FUNC

    qDebug() << "Wintun library loaded successfully";
    return true;
}

void WintunAdapter::unloadWintunLibrary() {
    if (m_wintunDll) {
        FreeLibrary(m_wintunDll);
        m_wintunDll = nullptr;
    }

    // Обнуляем все указатели
    pWintunCreateAdapter = nullptr;
    pWintunCloseAdapter = nullptr;
    pWintunStartSession = nullptr;
    pWintunEndSession = nullptr;
    pWintunAllocateSendPacket = nullptr;
    pWintunSendPacket = nullptr;
    pWintunReceivePacket = nullptr;
    pWintunReleaseReceivePacket = nullptr;
    pWintunGetReadWaitEvent = nullptr;
    pWintunGetRunningDriverVersion = nullptr;
}
