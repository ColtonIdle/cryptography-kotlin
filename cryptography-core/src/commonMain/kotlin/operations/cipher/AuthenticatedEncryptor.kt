/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray
    public suspend fun encrypt(plaintext: ByteString, associatedData: ByteString?): ByteString
    public suspend fun encrypt(plaintext: RawSource, associatedData: ByteString?): ByteString

    public fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray
    public fun encryptBlocking(plaintext: ByteString, associatedData: ByteString?): ByteString
    public fun encryptBlocking(plaintext: RawSource, associatedData: ByteString?): ByteString

    @ExperimentalCryptographyIoApi
    public fun encrypting(plaintext: RawSource, associatedData: ByteString?): RawSource

    @ExperimentalCryptographyIoApi
    public fun encrypting(ciphertext: RawSink, associatedData: ByteString?): RawSink

    // overrides for associatedData=null
    public override suspend fun encrypt(plaintext: ByteArray): ByteArray = encrypt(plaintext, null)
    public override suspend fun encrypt(plaintext: ByteString): ByteString = encrypt(plaintext, null)
    public override suspend fun encrypt(plaintext: RawSource): ByteString = encrypt(plaintext, null)
    public override fun encryptBlocking(plaintext: ByteArray): ByteArray = encryptBlocking(plaintext, null)
    public override fun encryptBlocking(plaintext: ByteString): ByteString = encryptBlocking(plaintext, null)
    public override fun encryptBlocking(plaintext: RawSource): ByteString = encryptBlocking(plaintext, null)

    @ExperimentalCryptographyIoApi
    public override fun encrypting(plaintext: RawSource): RawSource = encrypting(plaintext, null)

    @ExperimentalCryptographyIoApi
    public override fun encrypting(ciphertext: RawSink): RawSink = encrypting(ciphertext, null)
}
