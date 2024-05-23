/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray
    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString?): ByteString
    public suspend fun decrypt(ciphertext: RawSource, associatedData: ByteString?): ByteString

    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray
    public fun decryptBlocking(ciphertext: ByteString, associatedData: ByteString?): ByteString
    public fun decryptBlocking(ciphertext: RawSource, associatedData: ByteString?): ByteString

    @ExperimentalCryptographyIoApi
    public fun decrypting(ciphertext: RawSource, associatedData: ByteString?): RawSource

    @ExperimentalCryptographyIoApi
    public fun decrypting(plaintext: RawSink, associatedData: ByteString?): RawSink

    // overrides for associatedData=null
    public override suspend fun decrypt(ciphertext: ByteArray): ByteArray = decrypt(ciphertext, null)
    public override suspend fun decrypt(ciphertext: ByteString): ByteString = decrypt(ciphertext, null)
    public override suspend fun decrypt(ciphertext: RawSource): ByteString = decrypt(ciphertext, null)
    public override fun decryptBlocking(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext, null)
    public override fun decryptBlocking(ciphertext: ByteString): ByteString = decryptBlocking(ciphertext, null)
    public override fun decryptBlocking(ciphertext: RawSource): ByteString = decryptBlocking(ciphertext, null)

    @ExperimentalCryptographyIoApi
    public override fun decrypting(ciphertext: RawSource): RawSource = decrypting(ciphertext, null)

    @ExperimentalCryptographyIoApi
    public override fun decrypting(plaintext: RawSink): RawSink = decrypting(plaintext, null)
}
