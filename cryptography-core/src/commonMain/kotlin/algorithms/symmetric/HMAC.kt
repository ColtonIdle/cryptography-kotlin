package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<HMAC>("HMAC")

    public fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public fun signatureGenerator(): SignatureGenerator
        public fun signatureVerifier(): SignatureVerifier

        public enum class Format : KeyFormat { RAW, JWK }
    }
}