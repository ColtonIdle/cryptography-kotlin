/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal abstract class JdkPrivateKeyDecoder<KF : MaterialFormat, K : PrivateKey>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : MaterialDecoder<KF, K> {
    private val keyFactory = state.keyFactory(algorithm)

    protected fun decodeFromDer(input: ByteArray): K = keyFactory.use { it.generatePrivate(PKCS8EncodedKeySpec(input)) }.convert()

    protected abstract fun JPrivateKey.convert(): K
}
