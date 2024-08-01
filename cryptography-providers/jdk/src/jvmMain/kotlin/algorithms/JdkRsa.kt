/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

//rsa JDK uses slightly different names for hash algorithms
internal fun CryptographyAlgorithmId<Digest>.rsaHashAlgorithmName(): String = when (this) {
    SHA1     -> "SHA-1"
    SHA224   -> "SHA-224"
    SHA256   -> "SHA-256"
    SHA384   -> "SHA-384"
    SHA512   -> "SHA-512"
    SHA3_224 -> "SHA3-224"
    SHA3_256 -> "SHA3-256"
    SHA3_384 -> "SHA3-384"
    SHA3_512 -> "SHA3-512"
    else     -> throw CryptographyException("Unsupported hash algorithm: $this")
}

internal abstract class RsaPublicKeyDecoder<K : RSA.PublicKey>(
    state: JdkCryptographyState,
) : JdkPublicKeyDecoder<RSA.PublicKey.Format, K>(state, "RSA") {
    override fun decodeFrom(format: RSA.PublicKey.Format, data: ByteArray): K = decodeFromDer(
        when (format) {
            RSA.PublicKey.Format.JWK       -> error("$format is not supported")
            RSA.PublicKey.Format.DER       -> data
            RSA.PublicKey.Format.PEM       -> unwrapPem(PemLabel.PublicKey, data)
            RSA.PublicKey.Format.DER.PKCS1 -> wrapPublicKey(RsaKeyAlgorithmIdentifier, data)
            RSA.PublicKey.Format.PEM.PKCS1 -> wrapPublicKey(RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPublicKey, data))
        }
    )
}

internal abstract class RsaPrivateKeyDecoder<K : RSA.PrivateKey>(
    state: JdkCryptographyState,
) : JdkPrivateKeyDecoder<RSA.PrivateKey.Format, K>(state, "RSA") {
    override fun decodeFrom(format: RSA.PrivateKey.Format, data: ByteArray): K = decodeFromDer(
        when (format) {
            RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
            RSA.PrivateKey.Format.DER       -> data
            RSA.PrivateKey.Format.PEM       -> unwrapPem(PemLabel.PrivateKey, data)
            RSA.PrivateKey.Format.DER.PKCS1 -> wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, data)
            RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPrivateKey, data))
        }
    )
}

internal abstract class RsaPublicEncodableKey(
    key: JPublicKey,
) : JdkEncodableKey<RSA.PublicKey.Format>(key) {
    final override fun encoder(): MaterialSelfEncoder<RSA.PublicKey.Format> = object : MaterialSelfEncoder<RSA.PublicKey.Format> {
        override fun encodeTo(format: RSA.PublicKey.Format): ByteArray = when (format) {
            RSA.PublicKey.Format.JWK       -> error("$format is not supported")
            RSA.PublicKey.Format.DER       -> encodeToDer()
            RSA.PublicKey.Format.PEM       -> wrapPem(PemLabel.PublicKey, encodeToDer())
            RSA.PublicKey.Format.DER.PKCS1 -> unwrapPublicKey(ObjectIdentifier.RSA, encodeToDer())
            RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(
                PemLabel.RsaPublicKey,
                unwrapPublicKey(ObjectIdentifier.RSA, encodeToDer())
            )
        }
    }
}

internal abstract class RsaPrivateEncodableKey(
    key: JPrivateKey,
) : JdkEncodableKey<RSA.PrivateKey.Format>(key) {
    final override fun encoder(): MaterialSelfEncoder<RSA.PrivateKey.Format> = object : MaterialSelfEncoder<RSA.PrivateKey.Format> {
        override fun encodeTo(format: RSA.PrivateKey.Format): ByteArray = when (format) {
            RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
            RSA.PrivateKey.Format.DER       -> encodeToDer()
            RSA.PrivateKey.Format.PEM       -> wrapPem(PemLabel.PrivateKey, encodeToDer())
            RSA.PrivateKey.Format.DER.PKCS1 -> unwrapPrivateKey(ObjectIdentifier.RSA, encodeToDer())
            RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(
                PemLabel.RsaPrivateKey,
                unwrapPrivateKey(ObjectIdentifier.RSA, encodeToDer())
            )
        }
    }
}
