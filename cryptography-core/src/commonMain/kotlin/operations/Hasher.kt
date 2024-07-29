/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public fun hash(data: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncHasher {
    public suspend fun hash(data: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun hashBlocking(data: ByteArray): ByteArray
}

@CryptographyProviderApi
public fun Hasher.asAsync(): AsyncHasher = object : AsyncHasher {
    override suspend fun hash(data: ByteArray): ByteArray = this@asAsync.hash(data)
    override fun hashBlocking(data: ByteArray): ByteArray = this@asAsync.hash(data)
}
