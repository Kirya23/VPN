#include <QCoreApplication>
#include <QDebug>
#include <csignal>
#include "vpnclient.h"


// Глобальный указатель для обработки сигналов
static QCoreApplication* globalApp = nullptr;

void signalHandler(int signal) {
    qDebug() << "\n[STOP] Получен сигнал" << signal << "- завершаем работу...";
    if (globalApp) {
        globalApp->quit();
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);
    globalApp = &a;

    // Устанавливаем обработчики сигналов для Ctrl+C
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    qDebug() << "[INFO] VPN-клиент с Wintun";
    qDebug() << "=========================";

    VpnClient client;
    client.start("147.45.173.166", 8080);

    return a.exec();
}
