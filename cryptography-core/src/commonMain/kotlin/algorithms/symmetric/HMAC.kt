/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@Suppress("DEPRECATION_ERROR")
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<HMAC>("HMAC")

    @Deprecated(
        "Renamed to asyncKeyDecoder",
        ReplaceWith("asyncKeyDecoder(digest)"),
        DeprecationLevel.ERROR
    )
    public fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<Key.Format, Key> = asyncKeyDecoder(digest)
    public fun asyncKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<Key.Format, Key>

    @Deprecated(
        "Renamed to asyncKeyGenerator",
        ReplaceWith("asyncKeyGenerator(digest)"),
        DeprecationLevel.ERROR
    )
    public fun keyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key> = asyncKeyGenerator(digest)
    public fun asyncKeyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format>, SymmetricKey {
        public override fun encoder(): MaterialSelfEncoder<Format>
        public override fun asyncEncoder(): AsyncMaterialSelfEncoder<Format>

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

        public enum class Format : MaterialFormat { RAW, JWK }
    }
}
