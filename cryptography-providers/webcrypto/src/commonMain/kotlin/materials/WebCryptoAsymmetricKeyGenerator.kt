/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

@Suppress("DEPRECATION_ERROR")
internal class WebCryptoAsymmetricKeyGenerator<K : KeyPair>(
    private val algorithm: Algorithm,
    private val keyUsages: Array<String>,
    private val keyPairWrapper: (CryptoKeyPair) -> K,
) : KeyGenerator<K> {
    override suspend fun generate(): K {
        return keyPairWrapper(WebCrypto.generateKeyPair(algorithm, true, keyUsages))
    }

    override fun generateBlocking(): K = nonBlocking()
}
