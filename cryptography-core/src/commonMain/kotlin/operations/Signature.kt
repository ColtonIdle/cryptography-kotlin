/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("OperationsKt")

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlin.jvm.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public fun generateSignature(data: ByteArray): ByteArray
}

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public fun verifySignature(data: ByteArray, signature: ByteArray): Boolean
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSignatureGenerator {
    public suspend fun generateSignature(data: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun generateSignatureBlocking(data: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSignatureVerifier {
    public suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean

    // will be deprecated in 0.5.0
    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean
}

@CryptographyProviderApi
public fun SignatureGenerator.asAsync(): AsyncSignatureGenerator = object : AsyncSignatureGenerator {
    override suspend fun generateSignature(data: ByteArray): ByteArray = this@asAsync.generateSignature(data)
    override fun generateSignatureBlocking(data: ByteArray): ByteArray = this@asAsync.generateSignature(data)
}

@CryptographyProviderApi
public fun SignatureVerifier.asAsync(): AsyncSignatureVerifier = object : AsyncSignatureVerifier {
    override suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean =
        this@asAsync.verifySignature(data, signature)

    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean =
        this@asAsync.verifySignature(data, signature)
}
