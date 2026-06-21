#include <QCoreApplication>
#include <QDebug>
#include <csignal>
#include "vpnclient.h"


// Глобальный указатель для обработки сигналов
static QCoreApplication* globalApp = nullptr;

void signalHandler(int signal) {
    qDebug() << "\n🛑 Получен сигнал" << signal << "- завершаем работу...";
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

    qDebug() << "🛡️ VPN-клиент с Wintun";
    qDebug() << "=========================";

    VpnClient client;
    client.start("95.140.147.246", 8080);

    return a.exec();
}
