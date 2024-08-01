/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal abstract class JdkKeyPairGenerator<K : KeyPair>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : MaterialGenerator<K> {
    private val keyPairGenerator = state.keyPairGenerator(algorithm)

    protected abstract fun JKeyPairGenerator.init()

    protected abstract fun JKeyPair.convert(): K

    final override fun generate(): K = keyPairGenerator.use {
        it.init()
        it.generateKeyPair()
    }.convert()
}
