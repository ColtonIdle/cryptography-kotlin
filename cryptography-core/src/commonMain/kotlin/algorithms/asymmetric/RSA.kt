/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@Suppress("DEPRECATION_ERROR")
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface RSA<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {

    @Deprecated(
        "Renamed to asyncPublicKeyDecoder",
        ReplaceWith("asyncPublicKeyDecoder(digest)"),
        DeprecationLevel.ERROR
    )
    public fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<PublicKey.Format, PublicK> =
        asyncPublicKeyDecoder(digest)

    public fun asyncPublicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<PublicKey.Format, PublicK>

    @Deprecated(
        "Renamed to asyncPrivateKeyDecoder",
        ReplaceWith("asyncPrivateKeyDecoder(digest)"),
        DeprecationLevel.ERROR
    )
    public fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<PrivateKey.Format, PrivateK> =
        asyncPrivateKeyDecoder(digest)

    public fun asyncPrivateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<PrivateKey.Format, PrivateK>

    @Deprecated(
        "Renamed to asyncKeyPairGenerator",
        ReplaceWith("asyncKeyPairGenerator(keySize, digest, publicExponent)"),
        DeprecationLevel.ERROR
    )
    public fun keyPairGenerator(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
        publicExponent: BigInt = 65537.toBigInt(),
    ): KeyGenerator<KP> = asyncKeyPairGenerator(keySize, digest, publicExponent)

    public fun asyncKeyPairGenerator(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
        publicExponent: BigInt = 65537.toBigInt(),
    ): KeyGenerator<KP>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey> : dev.whyoleg.cryptography.materials.KeyPair {
        public override val publicKey: PublicK
        public override val privateKey: PrivateK
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format>, dev.whyoleg.cryptography.materials.PublicKey {
        public override fun encoder(): MaterialSelfEncoder<Format>
        public override fun asyncEncoder(): AsyncMaterialSelfEncoder<Format>

        public sealed class Format : MaterialFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public sealed class DER : Format() {
                // SPKI = SubjectPublicKeyInfo
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            public sealed class PEM : Format() {
                // SPKI = SubjectPublicKeyInfo
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format>, dev.whyoleg.cryptography.materials.PrivateKey {
        public override fun encoder(): MaterialSelfEncoder<Format>
        public override fun asyncEncoder(): AsyncMaterialSelfEncoder<Format>

        public sealed class Format : MaterialFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public sealed class DER : Format() {
                // via PrivateKeyInfo from PKCS8
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            public sealed class PEM : Format() {
                // via PrivateKeyInfo from PKCS8
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface OAEP : RSA<OAEP.PublicKey, OAEP.PrivateKey, OAEP.KeyPair> {
        override val id: CryptographyAlgorithmId<OAEP> get() = Companion

        public companion object : CryptographyAlgorithmId<OAEP>("RSA-OAEP")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            @Deprecated(
                "Renamed to asyncEncryptor",
                ReplaceWith("asyncEncryptor()"),
                DeprecationLevel.ERROR
            )
            public fun encryptor(): AsyncAuthenticatedEncryptor = asyncEncryptor()
            public fun asyncEncryptor(): AsyncAuthenticatedEncryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            @Deprecated(
                "Renamed to asyncDecryptor",
                ReplaceWith("asyncDecryptor()"),
                DeprecationLevel.ERROR
            )
            public fun decryptor(): AsyncAuthenticatedDecryptor = asyncDecryptor()
            public fun asyncDecryptor(): AsyncAuthenticatedDecryptor
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PSS : RSA<PSS.PublicKey, PSS.PrivateKey, PSS.KeyPair> {
        override val id: CryptographyAlgorithmId<PSS> get() = Companion

        public companion object : CryptographyAlgorithmId<PSS>("RSA-PSS")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            @Deprecated(
                "Renamed to asyncSignatureVerifier",
                ReplaceWith("asyncSignatureVerifier()"),
                DeprecationLevel.ERROR
            )
            public fun signatureVerifier(): AsyncSignatureVerifier = asyncSignatureVerifier()

            @Deprecated(
                "Renamed to asyncSignatureVerifier",
                ReplaceWith("asyncSignatureVerifier(saltSize)"),
                DeprecationLevel.ERROR
            )
            public fun signatureVerifier(saltSize: BinarySize): AsyncSignatureVerifier = asyncSignatureVerifier(saltSize)

            // default salt = digest.outputSize
            public fun asyncSignatureVerifier(): AsyncSignatureVerifier
            public fun asyncSignatureVerifier(saltSize: BinarySize): AsyncSignatureVerifier
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {

            @Deprecated(
                "Renamed to asyncSignatureGenerator",
                ReplaceWith("asyncSignatureGenerator()"),
                DeprecationLevel.ERROR
            )
            public fun signatureGenerator(): AsyncSignatureGenerator = asyncSignatureGenerator()

            @Deprecated(
                "Renamed to asyncSignatureGenerator",
                ReplaceWith("asyncSignatureGenerator(saltSize)"),
                DeprecationLevel.ERROR
            )
            public fun signatureGenerator(saltSize: BinarySize): AsyncSignatureGenerator = asyncSignatureGenerator(saltSize)

            // default salt = digest.outputSize
            public fun asyncSignatureGenerator(): AsyncSignatureGenerator
            public fun asyncSignatureGenerator(saltSize: BinarySize): AsyncSignatureGenerator
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PKCS1 : RSA<PKCS1.PublicKey, PKCS1.PrivateKey, PKCS1.KeyPair> {
        override val id: CryptographyAlgorithmId<PKCS1> get() = Companion

        public companion object : CryptographyAlgorithmId<PKCS1>("RSA-PKCS1-V1.5")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            @Deprecated(
                "Renamed to asyncSignatureVerifier",
                ReplaceWith("asyncSignatureVerifier()"),
                DeprecationLevel.ERROR
            )
            public fun signatureVerifier(): AsyncSignatureVerifier = asyncSignatureVerifier()
            public fun asyncSignatureVerifier(): AsyncSignatureVerifier

            // digest is not used at all
            @Deprecated(
                "Renamed to asyncEncryptor",
                ReplaceWith("asyncEncryptor()"),
                DeprecationLevel.ERROR
            )
            @DelicateCryptographyApi
            public fun encryptor(): AsyncEncryptor = asyncEncryptor()

            @DelicateCryptographyApi
            public fun asyncEncryptor(): AsyncEncryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            @Deprecated(
                "Renamed to asyncSignatureGenerator",
                ReplaceWith("asyncSignatureGenerator()"),
                DeprecationLevel.ERROR
            )
            public fun signatureGenerator(): AsyncSignatureGenerator = asyncSignatureGenerator()
            public fun asyncSignatureGenerator(): AsyncSignatureGenerator

            // digest is not used at all
            @Deprecated(
                "Renamed to asyncDecryptor",
                ReplaceWith("asyncDecryptor()"),
                DeprecationLevel.ERROR
            )
            @DelicateCryptographyApi
            public fun decryptor(): AsyncDecryptor = asyncDecryptor()

            @DelicateCryptographyApi
            public fun asyncDecryptor(): AsyncDecryptor
        }
    }

    // digest is not used at all
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface RAW : RSA<RAW.PublicKey, RAW.PrivateKey, RAW.KeyPair> {
        override val id: CryptographyAlgorithmId<RAW> get() = Companion

        public companion object : CryptographyAlgorithmId<RAW>("RSA-RAW")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            @Deprecated(
                "Renamed to asyncEncryptor",
                ReplaceWith("asyncEncryptor()"),
                DeprecationLevel.ERROR
            )
            public fun encryptor(): AsyncEncryptor = asyncEncryptor()
            public fun asyncEncryptor(): AsyncEncryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            @Deprecated(
                "Renamed to asyncDecryptor",
                ReplaceWith("asyncDecryptor()"),
                DeprecationLevel.ERROR
            )
            public fun decryptor(): AsyncDecryptor = asyncDecryptor()
            public fun asyncDecryptor(): AsyncDecryptor
        }
    }
}
