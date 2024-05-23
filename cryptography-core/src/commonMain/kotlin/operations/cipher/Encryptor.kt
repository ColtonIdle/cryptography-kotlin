/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public suspend fun encrypt(plaintext: ByteArray): ByteArray
    public suspend fun encrypt(plaintext: ByteString): ByteString
    public suspend fun encrypt(plaintext: RawSource): ByteString

    public fun encryptBlocking(plaintext: ByteArray): ByteArray
    public fun encryptBlocking(plaintext: ByteString): ByteString
    public fun encryptBlocking(plaintext: RawSource): ByteString

    @ExperimentalCryptographyIoApi
    public fun encrypting(plaintext: RawSource): RawSource

    @ExperimentalCryptographyIoApi
    public fun encrypting(ciphertext: RawSink): RawSink
}
