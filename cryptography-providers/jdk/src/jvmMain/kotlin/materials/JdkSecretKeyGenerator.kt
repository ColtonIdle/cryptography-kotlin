/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkSecretKeyGenerator<K : SymmetricKey>(
    state: JdkCryptographyState,
    algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
    private val keyGeneratorInit: JKeyGenerator.() -> Unit,
) : MaterialGenerator<K> {
    private val keyGenerator = state.keyGenerator(algorithm)
    override fun generate(): K = keyWrapper(keyGenerator.use {
        it.keyGeneratorInit()
        it.generateKey()
    })
}
