/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("OperationsKt")

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlin.jvm.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public fun encrypt(plaintext: ByteArray): ByteArray
}

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public fun decrypt(ciphertext: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncCipher : AsyncEncryptor, AsyncDecryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncEncryptor {
    public suspend fun encrypt(plaintext: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun encryptBlocking(plaintext: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncDecryptor {
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun decryptBlocking(ciphertext: ByteArray): ByteArray
}

@CryptographyProviderApi
public fun Encryptor.asAsync(): AsyncEncryptor = object : AsyncEncryptor {
    override suspend fun encrypt(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)
}

@CryptographyProviderApi
public fun Decryptor.asAsync(): AsyncDecryptor = object : AsyncDecryptor {
    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
}

@CryptographyProviderApi
public fun Cipher.asAsync(): AsyncCipher = object : AsyncCipher {
    override suspend fun encrypt(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)

    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
}
