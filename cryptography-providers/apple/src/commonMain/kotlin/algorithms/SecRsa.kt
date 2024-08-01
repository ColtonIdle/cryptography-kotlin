/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal abstract class SecRsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> :
    RSA<PublicK, PrivateK, KP> {

    protected abstract fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm?

    protected abstract fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): KP
    protected abstract fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): PublicK
    protected abstract fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): PrivateK

    final override fun asyncPublicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(hashAlgorithm(digest)).asAsync()

    private inner class RsaPublicKeyDecoder(private val algorithm: SecKeyAlgorithm?) : MaterialDecoder<RSA.PublicKey.Format, PublicK> {

        override fun decodeFrom(format: RSA.PublicKey.Format, data: ByteArray): PublicK {
            val pkcs1DerKey = when (format) {
                RSA.PublicKey.Format.JWK       -> error("$format is not supported")
                RSA.PublicKey.Format.DER.PKCS1 -> data
                RSA.PublicKey.Format.PEM.PKCS1 -> unwrapPem(PemLabel.RsaPublicKey, data)
                RSA.PublicKey.Format.DER       -> unwrapPublicKey(ObjectIdentifier.RSA, data)
                RSA.PublicKey.Format.PEM       -> unwrapPublicKey(ObjectIdentifier.RSA, unwrapPem(PemLabel.PublicKey, data))
            }

            val secKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                add(kSecAttrKeyClass, kSecAttrKeyClassPublic)
            }.use { attributes ->
                decodeSecKey(pkcs1DerKey, attributes)
            }

            return wrapPublicKey(algorithm, secKey)
        }
    }

    final override fun asyncPrivateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(hashAlgorithm(digest)).asAsync()

    private inner class RsaPrivateKeyDecoder(private val algorithm: SecKeyAlgorithm?) :
        MaterialDecoder<RSA.PrivateKey.Format, PrivateK> {

        override fun decodeFrom(format: RSA.PrivateKey.Format, data: ByteArray): PrivateK {
            val pkcs1DerKey = when (format) {
                RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
                RSA.PrivateKey.Format.DER.PKCS1 -> data
                RSA.PrivateKey.Format.PEM.PKCS1 -> unwrapPem(PemLabel.RsaPrivateKey, data)
                RSA.PrivateKey.Format.DER       -> unwrapPrivateKey(ObjectIdentifier.RSA, data)
                RSA.PrivateKey.Format.PEM       -> unwrapPrivateKey(ObjectIdentifier.RSA, unwrapPem(PemLabel.PrivateKey, data))
            }

            val secKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                add(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            }.use { attributes ->
                decodeSecKey(pkcs1DerKey, attributes)
            }

            return wrapPrivateKey(algorithm, secKey)
        }
    }

    @Suppress("DEPRECATION_ERROR")
    final override fun asyncKeyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> {
        check(publicExponent == 65537.toBigInt()) { "Only F4(default) public exponent is supported" }

        return RsaKeyGenerator(keySize.inBits, hashAlgorithm(digest)).asKeyGenerator()
    }

    private inner class RsaKeyGenerator(
        private val keySizeBits: Int,
        private val algorithm: SecKeyAlgorithm?,
    ) : MaterialGenerator<KP> {
        override fun generate(): KP {
            val privateKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                @Suppress("CAST_NEVER_SUCCEEDS")
                add(kSecAttrKeySizeInBits, (keySizeBits as NSNumber).retainBridge())
            }.use { attributes ->
                generateSecKey(attributes)
            }

            val publicKey = SecKeyCopyPublicKey(privateKey)!!
            return wrapKeyPair(algorithm, publicKey, privateKey)
        }
    }

    protected abstract class RsaPublicKey(
        protected val publicKey: SecKeyRef,
    ) : RSA.PublicKey {
        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(publicKey, SecKeyRef::release)
        override fun asyncEncoder(): AsyncMaterialSelfEncoder<RSA.PublicKey.Format> = encoder().asAsync()

        override fun encoder(): MaterialSelfEncoder<RSA.PublicKey.Format> = object : MaterialSelfEncoder<RSA.PublicKey.Format> {
            override fun encodeTo(format: RSA.PublicKey.Format): ByteArray {
                val pkcs1Key = exportSecKey(publicKey)

                return when (format) {
                    RSA.PublicKey.Format.JWK       -> error("$format is not supported")
                    RSA.PublicKey.Format.DER.PKCS1 -> pkcs1Key
                    RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPublicKey, pkcs1Key)
                    RSA.PublicKey.Format.DER       -> wrapPublicKey(RsaKeyAlgorithmIdentifier, pkcs1Key)
                    RSA.PublicKey.Format.PEM       -> wrapPem(PemLabel.PublicKey, wrapPublicKey(RsaKeyAlgorithmIdentifier, pkcs1Key))
                }
            }
        }
    }

    protected abstract class RsaPrivateKey(
        protected val privateKey: SecKeyRef,
    ) : RSA.PrivateKey {
        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(privateKey, SecKeyRef::release)

        override fun asyncEncoder(): AsyncMaterialSelfEncoder<RSA.PrivateKey.Format> = encoder().asAsync()

        override fun encoder(): MaterialSelfEncoder<RSA.PrivateKey.Format> = object : MaterialSelfEncoder<RSA.PrivateKey.Format> {
            override fun encodeTo(format: RSA.PrivateKey.Format): ByteArray {
                val pkcs1Key = exportSecKey(privateKey)

                return when (format) {
                    RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
                    RSA.PrivateKey.Format.DER.PKCS1 -> pkcs1Key
                    RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPrivateKey, pkcs1Key)
                    RSA.PrivateKey.Format.DER       -> wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, pkcs1Key)
                    RSA.PrivateKey.Format.PEM       -> wrapPem(PemLabel.PrivateKey, wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, pkcs1Key))
                }
            }
        }
    }
}
