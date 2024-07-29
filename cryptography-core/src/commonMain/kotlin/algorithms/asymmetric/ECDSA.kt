/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDSA : EC<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDSA>("ECDSA")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        @Deprecated(
            "Renamed to asyncSignatureVerifier",
            ReplaceWith("asyncSignatureVerifier(digest, format)"),
            DeprecationLevel.ERROR
        )
        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat,
        ): AsyncSignatureVerifier = asyncSignatureVerifier(digest, format)

        public fun asyncSignatureVerifier(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat,
        ): AsyncSignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        @Deprecated(
            "Renamed to asyncSignatureGenerator",
            ReplaceWith("asyncSignatureGenerator(digest, format)"),
            DeprecationLevel.ERROR
        )
        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat,
        ): AsyncSignatureGenerator = asyncSignatureGenerator(digest, format)

        public fun asyncSignatureGenerator(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat,
        ): AsyncSignatureGenerator
    }

    public enum class SignatureFormat {
        //IEEE P1363 / X9.63 format
        RAW,

        //X.509 format
        DER
    }
}
