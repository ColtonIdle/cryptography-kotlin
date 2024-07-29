/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public fun encrypt(plaintextInput: ByteArray): ByteArray
}

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public fun decrypt(ciphertextInput: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncCipher : AsyncEncryptor, AsyncDecryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncEncryptor {
    public suspend fun encrypt(plaintextInput: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun encryptBlocking(plaintextInput: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncDecryptor {
    public suspend fun decrypt(ciphertextInput: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun decryptBlocking(ciphertextInput: ByteArray): ByteArray
}

@CryptographyProviderApi
public fun Encryptor.asAsync(): AsyncEncryptor = object : AsyncEncryptor {
    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray = this@asAsync.encrypt(plaintextInput)
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = this@asAsync.encrypt(plaintextInput)
}

@CryptographyProviderApi
public fun Decryptor.asAsync(): AsyncDecryptor = object : AsyncDecryptor {
    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray = this@asAsync.decrypt(ciphertextInput)
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = this@asAsync.decrypt(ciphertextInput)
}

@CryptographyProviderApi
public fun Cipher.asAsync(): AsyncCipher = object : AsyncCipher {
    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray = this@asAsync.encrypt(plaintextInput)
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = this@asAsync.encrypt(plaintextInput)

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray = this@asAsync.decrypt(ciphertextInput)
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = this@asAsync.decrypt(ciphertextInput)
}
