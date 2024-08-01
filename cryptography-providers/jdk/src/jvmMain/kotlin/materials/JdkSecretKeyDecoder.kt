/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkSecretKeyDecoder<KF : MaterialFormat, K : SymmetricKey>(
    private val algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
) : MaterialDecoder<KF, K> {
    override fun decodeFrom(format: KF, data: ByteArray): K = when (format.name) {
        "RAW" -> keyWrapper(SecretKeySpec(data, algorithm))
        else  -> error("$format is not supported")
    }
}
