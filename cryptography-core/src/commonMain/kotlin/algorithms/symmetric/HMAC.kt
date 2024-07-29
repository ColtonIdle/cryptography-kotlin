/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<HMAC>("HMAC")

    public fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        @Deprecated(
            "Renamed to asyncSignatureGenerator",
            ReplaceWith("asyncSignatureGenerator()"),
            DeprecationLevel.ERROR
        )
        public fun signatureGenerator(): AsyncSignatureGenerator = asyncSignatureGenerator()

        @Deprecated(
            "Renamed to asyncSignatureVerifier",
            ReplaceWith("asyncSignatureVerifier()"),
            DeprecationLevel.ERROR
        )
        public fun signatureVerifier(): AsyncSignatureVerifier = asyncSignatureVerifier()

        public fun asyncSignatureGenerator(): AsyncSignatureGenerator
        public fun asyncSignatureVerifier(): AsyncSignatureVerifier

        public enum class Format : KeyFormat { RAW, JWK }
    }
}
