/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public suspend fun hash(data: ByteArray): ByteArray
    public suspend fun hash(data: ByteString): ByteString
    public suspend fun hash(data: RawSource): ByteString

    public fun hashBlocking(data: ByteArray): ByteArray
    public fun hashBlocking(data: ByteString): ByteString
    public fun hashBlocking(data: RawSource): ByteString

    @ExperimentalCryptographyIoApi
    public fun hashFunction(): HashFunction

    @ExperimentalCryptographyIoApi
    public fun hashing(data: RawSink): HashingSink

    @ExperimentalCryptographyIoApi
    public fun hashing(data: RawSource): HashingSource
}

// hash function could be reused after calling computeHash or reset and should be closed after it's not needed any more
@ExperimentalCryptographyIoApi
public interface HashFunction : AutoCloseable {
    public fun update(data: ByteString)

    // compute and reset the state
    public fun computeHash(): ByteString

    // just resets the state
    public fun reset()

    // update/compute will throw an error
    override fun close()
}

// closing it will close an underlying source and `computeHash` will start to throw
@ExperimentalCryptographyIoApi
public interface HashingSink : RawSink {
    // compute and reset the state
    public fun computeHash(): ByteString
}

// closing it will close an underlying source and `computeHash` will start to throw
@ExperimentalCryptographyIoApi
public interface HashingSource : RawSource {
    // compute and reset the state
    public fun computeHash(): ByteString
}
