/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import platform.Security.*

internal object SecRsaOaep : SecRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(), RSA.OAEP {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaOaepSecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.OAEP.KeyPair = RsaOaepKeyPair(
        publicKey = RsaOaepPublicKey(publicKey, algorithm),
        privateKey = RsaOaepPrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.OAEP.PublicKey = RsaOaepPublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.OAEP.PrivateKey = RsaOaepPrivateKey(key, algorithm)

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(
        publicKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.OAEP.PublicKey, AuthenticatedEncryptor {
        override fun asyncEncryptor(): AsyncAuthenticatedEncryptor = asAsync()
        override fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
            require(associatedData == null) { "Associated data inclusion is not supported" }

            return secEncrypt(publicKey, algorithm, plaintextInput)
        }
    }

    private class RsaOaepPrivateKey(
        privateKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.OAEP.PrivateKey, AuthenticatedDecryptor {
        override fun asyncDecryptor(): AsyncAuthenticatedDecryptor = asAsync()
        override fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
            require(associatedData == null) { "Associated data inclusion is not supported" }

            return secDecrypt(privateKey, algorithm, ciphertextInput)
        }
    }
}
