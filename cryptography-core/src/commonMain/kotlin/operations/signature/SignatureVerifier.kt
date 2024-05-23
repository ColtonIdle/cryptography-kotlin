/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean
    public suspend fun verifySignature(data: ByteString, signature: ByteString): Boolean
    public suspend fun verifySignature(data: RawSource, signature: ByteString): Boolean

    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean
    public fun verifySignatureBlocking(data: ByteString, signature: ByteString): Boolean
    public fun verifySignatureBlocking(data: RawSource, signature: ByteString): Boolean
}
