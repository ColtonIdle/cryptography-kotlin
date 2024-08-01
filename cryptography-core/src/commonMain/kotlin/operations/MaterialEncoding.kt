/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("OperationsKt")

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import kotlin.jvm.*

// not used until 0.5.0
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialDecoder<MF : MaterialFormat, M : Material> {
    public fun decodeFrom(format: MF, data: ByteArray): M
}

// encodes itself
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialSelfEncoder<MF : MaterialFormat> {
    public fun encodeTo(format: MF): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncMaterialDecoder<MF : MaterialFormat, M : Material> {
    public suspend fun decodeFrom(format: MF, data: ByteArray): M

    // will be deprecated in 0.5.0
    public fun decodeFromBlocking(format: MF, data: ByteArray): M
}

// encodes itself
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncMaterialSelfEncoder<MF : MaterialFormat> {
    public suspend fun encodeTo(format: MF): ByteArray
}

@CryptographyProviderApi
public fun <MF : MaterialFormat, M : Material> MaterialDecoder<MF, M>.asAsync(): AsyncMaterialDecoder<MF, M> =
    object : AsyncMaterialDecoder<MF, M> {
        override suspend fun decodeFrom(format: MF, data: ByteArray): M = this@asAsync.decodeFrom(format, data)
        override fun decodeFromBlocking(format: MF, data: ByteArray): M = this@asAsync.decodeFrom(format, data)
    }

@CryptographyProviderApi
public fun <MF : MaterialFormat> MaterialSelfEncoder<MF>.asAsync(): AsyncMaterialSelfEncoder<MF> =
    object : AsyncMaterialSelfEncoder<MF> {
        override suspend fun encodeTo(format: MF): ByteArray = this@asAsync.encodeTo(format)
    }
