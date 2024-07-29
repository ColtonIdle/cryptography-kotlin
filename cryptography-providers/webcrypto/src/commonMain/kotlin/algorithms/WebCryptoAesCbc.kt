/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.random.*

internal object WebCryptoAesCbc : WebCryptoAes<AES.CBC.Key>(
    algorithmName = "AES-CBC",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesCbcKey)
), AES.CBC {
    private class AesCbcKey(key: CryptoKey) : AesKey(key), AES.CBC.Key {
        override fun asyncCipher(padding: Boolean): AES.AsyncIvCipher {
            require(padding) { "Padding is required in WebCrypto" }
            return AesCbcCipher(key)
        }
    }
}

private const val ivSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(private val key: CryptoKey) : AES.AsyncIvCipher {

    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)
        return iv + encrypt(iv, plaintextInput)
    }

    @DelicateCryptographyApi
    override suspend fun encrypt(iv: ByteArray, plaintextInput: ByteArray): ByteArray {
        return WebCrypto.encrypt(
            algorithm = AesCbcCipherAlgorithm(iv),
            key = key,
            data = plaintextInput
        )
    }

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }

        return WebCrypto.decrypt(
            algorithm = AesCbcCipherAlgorithm(ciphertextInput.copyOfRange(0, ivSizeBytes)),
            key = key,
            data = ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        )
    }

    @DelicateCryptographyApi
    override suspend fun decrypt(iv: ByteArray, ciphertextInput: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return WebCrypto.decrypt(
            algorithm = AesCbcCipherAlgorithm(iv),
            key = key,
            data = ciphertextInput
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = nonBlocking()
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray = nonBlocking()
}
