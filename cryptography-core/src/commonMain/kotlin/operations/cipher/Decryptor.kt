/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray
    public suspend fun decrypt(ciphertext: ByteString): ByteString
    public suspend fun decrypt(ciphertext: RawSource): ByteString

    public fun decryptBlocking(ciphertext: ByteArray): ByteArray
    public fun decryptBlocking(ciphertext: ByteString): ByteString
    public fun decryptBlocking(ciphertext: RawSource): ByteString

    @ExperimentalCryptographyIoApi
    public fun decrypting(ciphertext: RawSource): RawSource

    @ExperimentalCryptographyIoApi
    public fun decrypting(plaintext: RawSink): RawSink
}
