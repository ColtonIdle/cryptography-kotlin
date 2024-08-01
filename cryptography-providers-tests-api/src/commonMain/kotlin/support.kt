/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

fun AlgorithmTestScope<*>.supportsDigest(digest: CryptographyAlgorithmId<Digest>): Boolean = supports {
    val sha3Algorithms = setOf(SHA3_224, SHA3_256, SHA3_384, SHA3_512)
    when {
        (digest == SHA224 || digest in sha3Algorithms) &&
                provider.isWebCrypto                                  -> digest.name
        digest in sha3Algorithms &&
                provider.isApple                                      -> digest.name
        digest in sha3Algorithms &&
                provider.isJdkDefault &&
                (platform.isJdk { major < 17 } || platform.isAndroid) -> "${digest.name} signatures on old JDK"
        else                                                          -> null
    }
}

fun AlgorithmTestScope<*>.supportsKeyFormat(format: MaterialFormat): Boolean = supports {
    when {
        // only WebCrypto supports JWK for now
        format.name == "JWK" &&
                !provider.isWebCrypto -> "JWK key format"
        else                          -> null
    }
}

// WebCrypto doesn't support encryption without padding
fun AlgorithmTestScope<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports {
    when {
        provider.isWebCrypto && !padding -> "no padding"
        else                             -> null
    }
}

// WebCrypto BROWSER(or only chromium) doesn't support 192bits
// https://bugs.chromium.org/p/chromium/issues/detail?id=533699
fun AlgorithmTestScope<out AES<*>>.supportsKeySize(keySizeBits: Int): Boolean = supports {
    when {
        provider.isWebCrypto && platform.isBrowser && keySizeBits == 192 -> "192 bits key"
        else                                                             -> null
    }
}

fun AlgorithmTestScope<RSA.PSS>.supportsSaltSize(saltSize: Int?): Boolean = supports {
    when {
        provider.isApple && saltSize != null -> "custom saltSize"
        else                                 -> null
    }
}

fun AlgorithmTestScope<RSA.OAEP>.supportsAssociatedData(associatedDataSize: Int?): Boolean = supports {
    when {
        provider.isApple && associatedDataSize != null -> "associatedData"
        else                                           -> null
    }
}

fun AlgorithmTestScope<RSA.PKCS1>.supportsEncryption(): Boolean = supports {
    when {
        provider.isWebCrypto -> "PKCS1 encryption"
        else                 -> null
    }
}

fun AlgorithmTestScope<out EC<*, *, *>>.supportsCurve(curve: EC.Curve): Boolean = supports {
    when {
        // JDK default, WebCrypto and Apple doesn't support secp256k1
        curve.name == "secp256k1" && (
                provider.isJdkDefault || provider.isWebCrypto || provider.isApple
                ) -> "ECDSA ${curve.name}"
        else      -> null
    }
}

fun AlgorithmTestScope<out EC<*, *, *>>.supportsDecoding(
    format: EC.PrivateKey.Format,
    key: ByteArray,
    otherContext: TestContext,
): Boolean = supports {
    fun supportedByAppleProvider(): Boolean {
        fun validateEcPrivateKey(bytes: ByteArray) = DER.decodeFromByteArray(EcPrivateKey.serializer(), bytes).publicKey != null
        fun decodePki(bytes: ByteArray): ByteArray = DER.decodeFromByteArray(PrivateKeyInfo.serializer(), bytes).privateKey

        return validateEcPrivateKey(
            when (format) {
                EC.PrivateKey.Format.JWK      -> return true
                EC.PrivateKey.Format.DER      -> decodePki(key)
                EC.PrivateKey.Format.DER.SEC1 -> key
                EC.PrivateKey.Format.PEM      -> decodePki(PEM.decode(key).bytes)
                EC.PrivateKey.Format.PEM.SEC1 -> PEM.decode(key).bytes
            }
        )
    }

    when {
        provider.isApple && !supportedByAppleProvider() -> "private key '$format' format without 'publicKey' from ${otherContext.provider}"
        else                                            -> null
    }
}

fun ProviderTestScope.supports(algorithmId: CryptographyAlgorithmId<*>): Boolean = validate {
    when {
        algorithmId == RSA.PSS &&
                provider.isJdkDefault &&
                platform.isAndroid                    -> "JDK provider on Android doesn't support RSASSA-PSS"
        provider.isJdkDefault &&
                platform.isAndroid { apiLevel == 21 } -> "JDK provider on Android API 21 is super unstable"
        (algorithmId == ECDH || algorithmId == ECDSA) &&
                provider.isJdkDefault &&
                platform.isAndroid { apiLevel == 27 } -> "Key encoding of EC DER private key on Android API 27 is flaky"
        else                                          -> null
    }
}

private fun ProviderTestScope.supports(condition: TestContext.() -> String?): Boolean {
    return validate { condition()?.let { "'$it' is not supported" } }
}

private fun ProviderTestScope.validate(condition: TestContext.() -> String?): Boolean {
    val reason = condition(context) ?: return true
    logger.print("SKIP: $reason")
    return false
}
