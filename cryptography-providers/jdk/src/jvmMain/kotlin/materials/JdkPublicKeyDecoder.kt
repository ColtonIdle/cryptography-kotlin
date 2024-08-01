/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal abstract class JdkPublicKeyDecoder<KF : MaterialFormat, K : PublicKey>(
    protected val state: JdkCryptographyState,
    algorithm: String,
    private val pemAlgorithm: String = algorithm,
) : MaterialDecoder<KF, K> {
    protected val keyFactory = state.keyFactory(algorithm)

    protected fun decodeFromDer(input: ByteArray): K = keyFactory.use { it.generatePublic(X509EncodedKeySpec(input)) }.convert()

    protected abstract fun JPublicKey.convert(): K
}
