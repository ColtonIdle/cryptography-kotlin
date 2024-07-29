/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoRsaOaep : WebCryptoRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(
    algorithmName = "RSA-OAEP",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt"), ::RsaOaepPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("decrypt"), ::RsaOaepPrivateKey),
    keyPairWrapper = ::RsaOaepKeyPair
), RSA.OAEP {
    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(publicKey: CryptoKey) : RsaPublicKey(publicKey), RSA.OAEP.PublicKey {
        override fun asyncEncryptor(): AsyncAuthenticatedEncryptor = RsaOaepEncryptor(publicKey)
    }

    private class RsaOaepPrivateKey(privateKey: CryptoKey) : RsaPrivateKey(privateKey), RSA.OAEP.PrivateKey {
        override fun asyncDecryptor(): AsyncAuthenticatedDecryptor = RsaOaepDecryptor(privateKey)
    }
}

private class RsaOaepEncryptor(private val key: CryptoKey) : AsyncAuthenticatedEncryptor {

    override suspend fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.encrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = plaintextInput
        )
    }

    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}

private class RsaOaepDecryptor(private val key: CryptoKey) : AsyncAuthenticatedDecryptor {

    override suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = ciphertextInput
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
