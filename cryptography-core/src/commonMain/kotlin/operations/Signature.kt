/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public fun generateSignature(dataInput: ByteArray): ByteArray
}

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSignatureGenerator {
    public suspend fun generateSignature(dataInput: ByteArray): ByteArray

    // will be deprecated in 0.5.0
    public fun generateSignatureBlocking(dataInput: ByteArray): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSignatureVerifier {
    public suspend fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean

    // will be deprecated in 0.5.0
    public fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean
}

@CryptographyProviderApi
public fun SignatureGenerator.asAsync(): AsyncSignatureGenerator = object : AsyncSignatureGenerator {
    override suspend fun generateSignature(dataInput: ByteArray): ByteArray = this@asAsync.generateSignature(dataInput)
    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = this@asAsync.generateSignature(dataInput)
}

@CryptographyProviderApi
public fun SignatureVerifier.asAsync(): AsyncSignatureVerifier = object : AsyncSignatureVerifier {
    override suspend fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean =
        this@asAsync.verifySignature(dataInput, signatureInput)

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean =
        this@asAsync.verifySignature(dataInput, signatureInput)
}
