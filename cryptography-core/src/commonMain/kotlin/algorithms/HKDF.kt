/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HKDF : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HKDF> get() = Companion

    public companion object : CryptographyAlgorithmId<HKDF>("HKDF")

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        salt: ByteArray?, // TODO: optional?
        outputSize: BinarySize,
    ): SecretDerivation

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface SecretDerivation : dev.whyoleg.cryptography.operations.SecretDerivation {
        // additional optional context
        public suspend fun deriveSecret(input: ByteArray, context: ByteArray? = null): ByteArray
        public fun deriveSecretBlocking(input: ByteArray, context: ByteArray? = null): ByteArray

        override suspend fun deriveSecret(input: ByteArray): ByteArray = deriveSecretBlocking(input, null)
        override fun deriveSecretBlocking(input: ByteArray): ByteArray = deriveSecretBlocking(input, null)
    }
}
