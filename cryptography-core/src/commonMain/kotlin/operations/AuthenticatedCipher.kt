/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedCipher : Cipher, AuthenticatedEncryptor, AuthenticatedDecryptor

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    // optional overloads
    override fun encrypt(plaintext: ByteArray): ByteArray = encrypt(plaintext, null)
}

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {
    public fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    // optional overloads
    override fun decrypt(ciphertext: ByteArray): ByteArray = decrypt(ciphertext, null)
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncAuthenticatedCipher : AsyncCipher, AsyncAuthenticatedEncryptor, AsyncAuthenticatedDecryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncAuthenticatedEncryptor : AsyncEncryptor {
    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    // will be deprecated in 0.5.0
    public fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    // optional overloads
    override suspend fun encrypt(plaintext: ByteArray): ByteArray = encrypt(plaintext, null)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = encryptBlocking(plaintext, null)
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncAuthenticatedDecryptor : AsyncDecryptor {
    public suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    // will be deprecated in 0.5.0
    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    // optional overloads
    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = decrypt(ciphertext, null)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext, null)
}

@CryptographyProviderApi
public fun AuthenticatedEncryptor.asAsync(): AsyncAuthenticatedEncryptor = object : AsyncAuthenticatedEncryptor {
    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.encrypt(plaintext, associatedData)

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.encrypt(plaintext, associatedData)
}

@CryptographyProviderApi
public fun AuthenticatedDecryptor.asAsync(): AsyncAuthenticatedDecryptor = object : AsyncAuthenticatedDecryptor {
    override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.decrypt(ciphertext, associatedData)

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.decrypt(ciphertext, associatedData)
}

@CryptographyProviderApi
public fun AuthenticatedCipher.asAsync(): AsyncAuthenticatedCipher = object : AsyncAuthenticatedCipher {
    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.encrypt(plaintext, associatedData)

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.encrypt(plaintext, associatedData)

    override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.decrypt(ciphertext, associatedData)

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray =
        this@asAsync.decrypt(ciphertext, associatedData)
}
