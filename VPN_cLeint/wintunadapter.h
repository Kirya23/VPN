#ifndef WINTUN_ADAPTER_H
#define WINTUN_ADAPTER_H

#include <QObject>
#include <QByteArray>
#include <windows.h>
#include <wintun.h>

class WintunAdapter : public QObject {
    Q_OBJECT
public:
    explicit WintunAdapter(QObject *parent = nullptr);
    ~WintunAdapter();

    // Создание и настройка адаптера
    bool initialize(const QString &adapterName = "MyVPN");
    bool start();
    void stop();

    // Отправка и получение пакетов
    bool sendPacket(const QByteArray &packet);
    QByteArray receivePacket();

    // Получение информации
    QString getAdapterName() const { return m_adapterName; }
    bool isRunning() const { return m_running; }

signals:
    void packetReceived(const QByteArray &packet);
    void errorOccurred(const QString &error);
    void adapterReady();

private:
    // Динамически загружаемые функции Wintun
    typedef WINTUN_ADAPTER_HANDLE (WINAPI *WintunCreateAdapter_t)(const WCHAR *, const WCHAR *, const GUID *);
    typedef WINTUN_ADAPTER_HANDLE (WINAPI *WintunOpenAdapter_t)(const WCHAR *);  // 👈 ДОБАВИТЬ ЭТУ СТРОКУ
    typedef void (WINAPI *WintunCloseAdapter_t)(WINTUN_ADAPTER_HANDLE);
    typedef WINTUN_SESSION_HANDLE (WINAPI *WintunStartSession_t)(WINTUN_ADAPTER_HANDLE, DWORD);
    typedef void (WINAPI *WintunEndSession_t)(WINTUN_SESSION_HANDLE);
    typedef BYTE* (WINAPI *WintunAllocateSendPacket_t)(WINTUN_SESSION_HANDLE, DWORD);
    typedef void (WINAPI *WintunSendPacket_t)(WINTUN_SESSION_HANDLE, BYTE*);
    typedef BYTE* (WINAPI *WintunReceivePacket_t)(WINTUN_SESSION_HANDLE, DWORD*);
    typedef void (WINAPI *WintunReleaseReceivePacket_t)(WINTUN_SESSION_HANDLE, BYTE*);
    typedef HANDLE (WINAPI *WintunGetReadWaitEvent_t)(WINTUN_SESSION_HANDLE);
    typedef DWORD (WINAPI *WintunGetRunningDriverVersion_t)(void);

    // Загрузка библиотеки и функций
    bool loadWintunLibrary();
    void unloadWintunLibrary();

    // Рабочий поток для чтения пакетов
    void readerThreadFunction();

    HMODULE m_wintunDll;
    WINTUN_ADAPTER_HANDLE m_adapter;
    WINTUN_SESSION_HANDLE m_session;
    HANDLE m_readThread;
    HANDLE m_stopEvent;

    QString m_adapterName;
    bool m_running;

    // Указатели на функции Wintun
    WintunCreateAdapter_t pWintunCreateAdapter;
    WintunOpenAdapter_t pWintunOpenAdapter;
    WintunCloseAdapter_t pWintunCloseAdapter;
    WintunStartSession_t pWintunStartSession;
    WintunEndSession_t pWintunEndSession;
    WintunAllocateSendPacket_t pWintunAllocateSendPacket;
    WintunSendPacket_t pWintunSendPacket;
    WintunReceivePacket_t pWintunReceivePacket;
    WintunReleaseReceivePacket_t pWintunReleaseReceivePacket;
    WintunGetReadWaitEvent_t pWintunGetReadWaitEvent;
    WintunGetRunningDriverVersion_t pWintunGetRunningDriverVersion;
};

#endif // WINTUN_ADAPTER_H
