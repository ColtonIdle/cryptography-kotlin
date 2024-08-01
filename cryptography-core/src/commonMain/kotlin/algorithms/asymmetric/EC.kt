/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import kotlin.jvm.*

@Suppress("DEPRECATION_ERROR")
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EC<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {

    @Deprecated(
        "Renamed to asyncPublicKeyDecoder",
        ReplaceWith("asyncPublicKeyDecoder(curve)"),
        DeprecationLevel.ERROR
    )
    public fun publicKeyDecoder(curve: Curve): AsyncMaterialDecoder<PublicKey.Format, PublicK> = asyncPublicKeyDecoder(curve)
    public fun asyncPublicKeyDecoder(curve: Curve): AsyncMaterialDecoder<PublicKey.Format, PublicK>

    @Deprecated(
        "Renamed to asyncPrivateKeyDecoder",
        ReplaceWith("asyncPrivateKeyDecoder(curve)"),
        DeprecationLevel.ERROR
    )
    public fun privateKeyDecoder(curve: Curve): AsyncMaterialDecoder<PrivateKey.Format, PrivateK> = asyncPrivateKeyDecoder(curve)
    public fun asyncPrivateKeyDecoder(curve: Curve): AsyncMaterialDecoder<PrivateKey.Format, PrivateK>

    @Deprecated(
        "Renamed to asyncKeyPairGenerator",
        ReplaceWith("asyncKeyPairGenerator(curve)"),
        DeprecationLevel.ERROR
    )
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KP> = asyncKeyPairGenerator(curve)
    public fun asyncKeyPairGenerator(curve: Curve): KeyGenerator<KP>

    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P256: Curve get() = Curve("P-256")
            public val P384: Curve get() = Curve("P-384")
            public val P521: Curve get() = Curve("P-521")
        }
    }

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

            // only uncompressed format is supported
            // format defined in X963: 04 | X | Y
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object PEM : Format() {
                override val name: String get() = "PEM"
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

                // via ECPrivateKey structure / RFC 5915
                public data object SEC1 : DER() {
                    override val name: String get() = "DER/SEC1"
                }
            }

            public sealed class PEM : Format() {
                // via PrivateKeyInfo from PKCS8
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                // via ECPrivateKey structure / RFC 5915
                public data object SEC1 : PEM() {
                    override val name: String get() = "PEM/SEC1"
                }
            }
        }
    }
}
