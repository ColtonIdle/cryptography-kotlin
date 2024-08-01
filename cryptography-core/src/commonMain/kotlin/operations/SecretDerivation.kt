/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("OperationsKt")

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import kotlin.jvm.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation<M : Material> {
    public fun deriveSecret(other: M): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSecretDerivation<M : Material> {
    public suspend fun deriveSecret(other: M): ByteArray
}

@CryptographyProviderApi
public fun <M : Material> SecretDerivation<M>.asAsync(): AsyncSecretDerivation<M> = object : AsyncSecretDerivation<M> {
    override suspend fun deriveSecret(other: M): ByteArray = this@asAsync.deriveSecret(other)
}
