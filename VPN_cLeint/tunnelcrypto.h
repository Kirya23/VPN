#ifndef TUNNELCRYPTO_H
#define TUNNELCRYPTO_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

struct TunnelSessionKeys {
    QByteArray txKey;
    QByteArray rxKey;
    quint32 txNoncePrefix = 0;
    quint32 rxNoncePrefix = 0;
};

class TunnelCrypto {
public:
    static constexpr int kPublicKeySize = 32;
    static constexpr int kPrivateKeySize = 32;
    static constexpr int kRandomSize = 32;
    static constexpr int kKeySize = 32;
    static constexpr int kAuthTagSize = 16;

    static bool generateX25519KeyPair(QByteArray *publicKey, QByteArray *privateKey, QString *error = nullptr);
    static bool randomBytes(int size, QByteArray *bytes, QString *error = nullptr);
    static bool deriveClientSessionKeys(const QByteArray &clientPrivateKey,
                                        const QByteArray &clientPublicKey,
                                        const QByteArray &clientRandom,
                                        const QByteArray &serverPublicKey,
                                        const QByteArray &serverRandom,
                                        TunnelSessionKeys *keys,
                                        QString *error = nullptr);
    static bool encryptPacket(const QByteArray &key,
                              quint32 noncePrefix,
                              quint64 sequence,
                              const QByteArray &aad,
                              const QByteArray &plaintext,
                              QByteArray *ciphertext,
                              QByteArray *authTag,
                              QString *error = nullptr);
    static bool decryptPacket(const QByteArray &key,
                              quint32 noncePrefix,
                              quint64 sequence,
                              const QByteArray &aad,
                              const QByteArray &ciphertext,
                              const QByteArray &authTag,
                              QByteArray *plaintext,
                              QString *error = nullptr);
};

#endif // TUNNELCRYPTO_H
