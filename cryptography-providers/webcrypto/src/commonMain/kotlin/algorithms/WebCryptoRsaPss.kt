/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoRsaPss : WebCryptoRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(
    algorithmName = "RSA-PSS",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf("verify"), ::RsaPssPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("sign"), ::RsaPssPrivateKey),
    keyPairWrapper = ::RsaPssKeyPair
), RSA.PSS {
    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(publicKey: CryptoKey) : RsaPublicKey(publicKey), RSA.PSS.PublicKey {
        override fun asyncSignatureVerifier(): AsyncSignatureVerifier {
            return asyncSignatureVerifier(hashSize(publicKey.algorithm.rsaKeyAlgorithmHashName).bytes)
        }

        override fun asyncSignatureVerifier(saltLength: BinarySize): AsyncSignatureVerifier {
            return WebCryptoSignatureVerifier(RsaPssSignatureAlgorithm(saltLength.inBytes), publicKey)
        }
    }

    private class RsaPssPrivateKey(privateKey: CryptoKey) : RsaPrivateKey(privateKey), RSA.PSS.PrivateKey {
        override fun asyncSignatureGenerator(): AsyncSignatureGenerator {
            return asyncSignatureGenerator(hashSize(privateKey.algorithm.rsaKeyAlgorithmHashName).bytes)
        }

        override fun asyncSignatureGenerator(saltLength: BinarySize): AsyncSignatureGenerator {
            return WebCryptoSignatureGenerator(RsaPssSignatureAlgorithm(saltLength.inBytes), privateKey)
        }
    }
}
