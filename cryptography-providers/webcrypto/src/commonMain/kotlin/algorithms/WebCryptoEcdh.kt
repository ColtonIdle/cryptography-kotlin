/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoEcdh : WebCryptoEc<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>(
    algorithmName = "ECDH",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf(), ::EcdhPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("deriveBits"), ::EcdhPrivateKey),
    keyPairWrapper = ::EcdhKeyPair
), ECDH {
    private class EcdhKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private class EcdhPublicKey(
        publicKey: CryptoKey,
    ) : EcPublicKey(publicKey), ECDH.PublicKey, AsyncSecretDerivation<ECDH.PrivateKey> {
        override fun asyncSecretDerivation(): AsyncSecretDerivation<ECDH.PrivateKey> = this
        override fun secretDerivation(): SecretDerivation<ECDH.PrivateKey> = nonBlocking()

        override suspend fun deriveSecret(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey)
            return WebCrypto.deriveBits(
                algorithm = EcdhKeyDeriveAlgorithm(publicKey),
                baseKey = other.privateKey,
                length = curveOrderSize(publicKey.algorithm.ecKeyAlgorithmNamedCurve) * 8
            )
        }
    }

    private class EcdhPrivateKey(
        privateKey: CryptoKey,
    ) : EcPrivateKey(privateKey), ECDH.PrivateKey, AsyncSecretDerivation<ECDH.PublicKey> {
        override fun asyncSecretDerivation(): AsyncSecretDerivation<ECDH.PublicKey> = this
        override fun secretDerivation(): SecretDerivation<ECDH.PublicKey> = nonBlocking()

        override suspend fun deriveSecret(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey)
            return WebCrypto.deriveBits(
                algorithm = EcdhKeyDeriveAlgorithm(other.publicKey),
                baseKey = privateKey,
                length = curveOrderSize(privateKey.algorithm.ecKeyAlgorithmNamedCurve) * 8
            )
        }
    }
}
