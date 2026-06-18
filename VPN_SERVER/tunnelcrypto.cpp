#include "tunnelcrypto.h"

#include <cstring>
#include <QtEndian>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace {

QString opensslErrorString(const QString &prefix) {
    const unsigned long errorCode = ERR_get_error();
    if (errorCode == 0) {
        return prefix;
    }

    char buffer[256] = {};
    ERR_error_string_n(errorCode, buffer, sizeof(buffer));
    return QStringLiteral("%1: %2").arg(prefix, QString::fromLatin1(buffer));
}

QByteArray buildNonce(quint32 prefix, quint64 sequence) {
    QByteArray nonce(12, Qt::Uninitialized);

    const quint32 bePrefix = qToBigEndian(prefix);
    const quint64 beSequence = qToBigEndian(sequence);

    memcpy(nonce.data(), &bePrefix, sizeof(bePrefix));
    memcpy(nonce.data() + sizeof(bePrefix), &beSequence, sizeof(beSequence));

    return nonce;
}

bool hmacSha256(const QByteArray &key, const QByteArray &data, QByteArray *digest, QString *error) {
    if (!digest) {
        if (error) {
            *error = QStringLiteral("Выходной буфер для HMAC не задан");
        }
        return false;
    }

    unsigned int digestSize = EVP_MD_size(EVP_sha256());
    QByteArray out(static_cast<int>(digestSize), Qt::Uninitialized);

    if (!HMAC(EVP_sha256(),
              key.constData(),
              key.size(),
              reinterpret_cast<const unsigned char *>(data.constData()),
              data.size(),
              reinterpret_cast<unsigned char *>(out.data()),
              &digestSize)) {
        if (error) {
            *error = opensslErrorString(QStringLiteral("Ошибка HMAC-SHA256"));
        }
        return false;
    }

    out.resize(static_cast<int>(digestSize));
    *digest = out;
    return true;
}

bool hkdfSha256(const QByteArray &salt,
                const QByteArray &ikm,
                const QByteArray &info,
                int outputLength,
                QByteArray *output,
                QString *error) {
    if (!output) {
        if (error) {
            *error = QStringLiteral("Выходной буфер HKDF не задан");
        }
        return false;
    }

    QByteArray effectiveSalt = salt;
    if (effectiveSalt.isEmpty()) {
        effectiveSalt = QByteArray(EVP_MD_size(EVP_sha256()), '\0');
    }

    QByteArray prk;
    if (!hmacSha256(effectiveSalt, ikm, &prk, error)) {
        return false;
    }

    QByteArray okm;
    okm.reserve(outputLength);

    QByteArray previousBlock;
    quint8 counter = 1;

    while (okm.size() < outputLength) {
        QByteArray blockInput = previousBlock;
        blockInput.append(info);
        blockInput.append(static_cast<char>(counter));

        QByteArray currentBlock;
        if (!hmacSha256(prk, blockInput, &currentBlock, error)) {
            return false;
        }

        okm.append(currentBlock);
        previousBlock = currentBlock;
        ++counter;
    }

    okm.resize(outputLength);
    *output = okm;
    return true;
}

bool deriveSharedSecret(const QByteArray &privateKey,
                        const QByteArray &peerPublicKey,
                        QByteArray *sharedSecret,
                        QString *error) {
    if (!sharedSecret) {
        if (error) {
            *error = QStringLiteral("Выходной буфер для общего секрета не задан");
        }
        return false;
    }

    EVP_PKEY *privatePkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,
                                                         nullptr,
                                                         reinterpret_cast<const unsigned char *>(privateKey.constData()),
                                                         privateKey.size());
    if (!privatePkey) {
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось создать приватный ключ X25519"));
        }
        return false;
    }

    EVP_PKEY *peerPkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                                     nullptr,
                                                     reinterpret_cast<const unsigned char *>(peerPublicKey.constData()),
                                                     peerPublicKey.size());
    if (!peerPkey) {
        EVP_PKEY_free(privatePkey);
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось создать публичный ключ X25519 удалённой стороны"));
        }
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privatePkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peerPkey);
        EVP_PKEY_free(privatePkey);
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось создать контекст X25519"));
        }
        return false;
    }

    bool success = false;
    do {
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось инициализировать X25519 derive"));
            }
            break;
        }

        if (EVP_PKEY_derive_set_peer(ctx, peerPkey) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось задать ключ удалённой стороны для X25519"));
            }
            break;
        }

        size_t secretLength = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLength) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось определить размер общего секрета X25519"));
            }
            break;
        }

        QByteArray secret(static_cast<int>(secretLength), Qt::Uninitialized);
        if (EVP_PKEY_derive(ctx,
                            reinterpret_cast<unsigned char *>(secret.data()),
                            &secretLength) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось вычислить общий секрет X25519"));
            }
            break;
        }

        secret.resize(static_cast<int>(secretLength));
        *sharedSecret = secret;
        success = true;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerPkey);
    EVP_PKEY_free(privatePkey);
    return success;
}

bool runAeadCipher(bool encrypt,
                   const QByteArray &key,
                   quint32 noncePrefix,
                   quint64 sequence,
                   const QByteArray &aad,
                   const QByteArray &input,
                   QByteArray *output,
                   QByteArray *authTag,
                   QString *error) {
    if (!output || !authTag) {
        if (error) {
            *error = QStringLiteral("Выходные буферы AEAD не заданы");
        }
        return false;
    }

    if (key.size() != TunnelCrypto::kKeySize) {
        if (error) {
            *error = QStringLiteral("Некорректная длина ключа AEAD");
        }
        return false;
    }

    if (!encrypt && authTag->size() != TunnelCrypto::kAuthTagSize) {
        if (error) {
            *error = QStringLiteral("Некорректная длина тега аутентичности");
        }
        return false;
    }

    const QByteArray nonce = buildNonce(noncePrefix, sequence);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось создать контекст ChaCha20-Poly1305"));
        }
        return false;
    }

    bool success = false;
    do {
        if (encrypt) {
            if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось инициализировать шифрование ChaCha20-Poly1305"));
                }
                break;
            }

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось задать длину nonce для шифрования"));
                }
                break;
            }

            if (EVP_EncryptInit_ex(ctx,
                                   nullptr,
                                   nullptr,
                                   reinterpret_cast<const unsigned char *>(key.constData()),
                                   reinterpret_cast<const unsigned char *>(nonce.constData())) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось задать ключ и nonce для шифрования"));
                }
                break;
            }
        } else {
            if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось инициализировать дешифрование ChaCha20-Poly1305"));
                }
                break;
            }

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось задать длину nonce для дешифрования"));
                }
                break;
            }

            if (EVP_DecryptInit_ex(ctx,
                                   nullptr,
                                   nullptr,
                                   reinterpret_cast<const unsigned char *>(key.constData()),
                                   reinterpret_cast<const unsigned char *>(nonce.constData())) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось задать ключ и nonce для дешифрования"));
                }
                break;
            }
        }

        int outLength = 0;
        if (!aad.isEmpty()) {
            if ((encrypt
                     ? EVP_EncryptUpdate(ctx,
                                         nullptr,
                                         &outLength,
                                         reinterpret_cast<const unsigned char *>(aad.constData()),
                                         aad.size())
                     : EVP_DecryptUpdate(ctx,
                                         nullptr,
                                         &outLength,
                                         reinterpret_cast<const unsigned char *>(aad.constData()),
                                         aad.size())) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось обработать AAD"));
                }
                break;
            }
        }

        QByteArray transformed(input.size(), Qt::Uninitialized);
        if ((encrypt
                 ? EVP_EncryptUpdate(ctx,
                                     reinterpret_cast<unsigned char *>(transformed.data()),
                                     &outLength,
                                     reinterpret_cast<const unsigned char *>(input.constData()),
                                     input.size())
                 : EVP_DecryptUpdate(ctx,
                                     reinterpret_cast<unsigned char *>(transformed.data()),
                                     &outLength,
                                     reinterpret_cast<const unsigned char *>(input.constData()),
                                     input.size())) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось обработать полезную нагрузку AEAD"));
            }
            break;
        }
        transformed.resize(outLength);

        int finalLength = 0;
        if (encrypt) {
            if (EVP_EncryptFinal_ex(ctx,
                                    reinterpret_cast<unsigned char *>(transformed.data()) + transformed.size(),
                                    &finalLength) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось завершить шифрование AEAD"));
                }
                break;
            }

            QByteArray tag(TunnelCrypto::kAuthTagSize, Qt::Uninitialized);
            if (EVP_CIPHER_CTX_ctrl(ctx,
                                    EVP_CTRL_AEAD_GET_TAG,
                                    tag.size(),
                                    tag.data()) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось получить тег аутентичности AEAD"));
                }
                break;
            }

            *output = transformed;
            *authTag = tag;
            success = true;
        } else {
            if (EVP_CIPHER_CTX_ctrl(ctx,
                                    EVP_CTRL_AEAD_SET_TAG,
                                    authTag->size(),
                                    authTag->data()) <= 0) {
                if (error) {
                    *error = opensslErrorString(QStringLiteral("Не удалось задать тег аутентичности AEAD"));
                }
                break;
            }

            if (EVP_DecryptFinal_ex(ctx,
                                    reinterpret_cast<unsigned char *>(transformed.data()) + transformed.size(),
                                    &finalLength) <= 0) {
                if (error) {
                    *error = QStringLiteral("Проверка тега аутентичности AEAD не прошла");
                }
                break;
            }

            *output = transformed;
            success = true;
        }
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

} // namespace

bool TunnelCrypto::generateX25519KeyPair(QByteArray *publicKey, QByteArray *privateKey, QString *error) {
    if (!publicKey || !privateKey) {
        if (error) {
            *error = QStringLiteral("Буферы для ключевой пары X25519 не заданы");
        }
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось создать контекст генерации X25519"));
        }
        return false;
    }

    EVP_PKEY *pkey = nullptr;
    bool success = false;

    do {
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось инициализировать генерацию X25519"));
            }
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось сгенерировать ключевую пару X25519"));
            }
            break;
        }

        QByteArray generatedPublicKey(kPublicKeySize, Qt::Uninitialized);
        size_t publicKeySize = generatedPublicKey.size();
        if (EVP_PKEY_get_raw_public_key(pkey,
                                        reinterpret_cast<unsigned char *>(generatedPublicKey.data()),
                                        &publicKeySize) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось получить публичный ключ X25519"));
            }
            break;
        }

        QByteArray generatedPrivateKey(kPrivateKeySize, Qt::Uninitialized);
        size_t privateKeySize = generatedPrivateKey.size();
        if (EVP_PKEY_get_raw_private_key(pkey,
                                         reinterpret_cast<unsigned char *>(generatedPrivateKey.data()),
                                         &privateKeySize) <= 0) {
            if (error) {
                *error = opensslErrorString(QStringLiteral("Не удалось получить приватный ключ X25519"));
            }
            break;
        }

        generatedPublicKey.resize(static_cast<int>(publicKeySize));
        generatedPrivateKey.resize(static_cast<int>(privateKeySize));

        *publicKey = generatedPublicKey;
        *privateKey = generatedPrivateKey;
        success = true;
    } while (false);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return success;
}

bool TunnelCrypto::randomBytes(int size, QByteArray *bytes, QString *error) {
    if (!bytes) {
        if (error) {
            *error = QStringLiteral("Буфер для случайных байтов не задан");
        }
        return false;
    }

    QByteArray randomData(size, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(randomData.data()), size) != 1) {
        if (error) {
            *error = opensslErrorString(QStringLiteral("Не удалось получить криптографически стойкие случайные байты"));
        }
        return false;
    }

    *bytes = randomData;
    return true;
}

bool TunnelCrypto::deriveServerSessionKeys(const QByteArray &serverPrivateKey,
                                           const QByteArray &serverPublicKey,
                                           const QByteArray &serverRandom,
                                           const QByteArray &clientPublicKey,
                                           const QByteArray &clientRandom,
                                           TunnelSessionKeys *keys,
                                           QString *error) {
    if (!keys) {
        if (error) {
            *error = QStringLiteral("Выходная структура ключей не задана");
        }
        return false;
    }

    QByteArray sharedSecret;
    if (!deriveSharedSecret(serverPrivateKey, clientPublicKey, &sharedSecret, error)) {
        return false;
    }

    QByteArray salt = clientRandom;
    salt.append(serverRandom);

    QByteArray info = QByteArrayLiteral("qt-vpn-mvp-handshake");
    info.append(clientPublicKey);
    info.append(serverPublicKey);

    QByteArray derived;
    if (!hkdfSha256(salt, sharedSecret, info, 72, &derived, error)) {
        return false;
    }

    keys->rxKey = derived.mid(0, kKeySize);
    keys->txKey = derived.mid(kKeySize, kKeySize);
    keys->rxNoncePrefix = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(derived.constData() + 64));
    keys->txNoncePrefix = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(derived.constData() + 68));

    return true;
}

bool TunnelCrypto::encryptPacket(const QByteArray &key,
                                 quint32 noncePrefix,
                                 quint64 sequence,
                                 const QByteArray &aad,
                                 const QByteArray &plaintext,
                                 QByteArray *ciphertext,
                                 QByteArray *authTag,
                                 QString *error) {
    return runAeadCipher(true, key, noncePrefix, sequence, aad, plaintext, ciphertext, authTag, error);
}

bool TunnelCrypto::decryptPacket(const QByteArray &key,
                                 quint32 noncePrefix,
                                 quint64 sequence,
                                 const QByteArray &aad,
                                 const QByteArray &ciphertext,
                                 const QByteArray &authTag,
                                 QByteArray *plaintext,
                                 QString *error) {
    QByteArray tagCopy = authTag;
    return runAeadCipher(false, key, noncePrefix, sequence, aad, ciphertext, plaintext, &tagCopy, error);
}
