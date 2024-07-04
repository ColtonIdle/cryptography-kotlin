/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun publicKeyDecoder(): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): KeyDecoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(
        primeModulus: BigInt,
        generator: BigInt,
        privateLength: BinarySize, // TODO: better name
    ): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Key {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        public fun sharedSecretDerivation(): SharedSecretDerivation<PrivateKey>
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        public fun sharedSecretDerivation(): SharedSecretDerivation<PublicKey>
    }
}
