/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkMacSignature(
    state: JdkCryptographyState,
    private val key: JSecretKey,
    algorithm: String,
) : SignatureGenerator, SignatureVerifier {
    private val mac = state.mac(algorithm)

    override fun generateSignature(dataInput: ByteArray): ByteArray = mac.use { mac ->
        mac.init(key)
        mac.doFinal(dataInput)
    }

    override fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return generateSignature(dataInput).contentEquals(signatureInput)
    }
}
