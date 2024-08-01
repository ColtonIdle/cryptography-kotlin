/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

@Suppress("DEPRECATION_ERROR")
internal class WebCryptoSymmetricKeyGenerator<K : SymmetricKey>(
    private val algorithm: Algorithm,
    private val keyWrapper: WebCryptoKeyWrapper<K>,
) : KeyGenerator<K> {
    override suspend fun generate(): K = keyWrapper.wrap(
        WebCrypto.generateKey(
            algorithm = algorithm,
            extractable = true,
            keyUsages = keyWrapper.usages
        )
    )

    override fun generateBlocking(): K = nonBlocking()
}
