/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkDigest(
    state: JdkCryptographyState,
    algorithm: String,
    override val id: CryptographyAlgorithmId<Digest>,
) : Digest, Hasher {
    override fun asyncHasher(): AsyncHasher = asAsync()
    private val messageDigest = state.messageDigest(algorithm)

    override fun hash(data: ByteArray): ByteArray = messageDigest.use { messageDigest ->
        messageDigest.reset()
        messageDigest.digest(data)
    }
}
