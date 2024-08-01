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
public interface MaterialGenerator<M : Material> {
    public fun generate(): M
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncMaterialGenerator<M : Material> {
    public suspend fun generate(): M

    // will be deprecated in 0.5.0
    public fun generateBlocking(): M
}

@CryptographyProviderApi
public fun <M : Material> MaterialGenerator<M>.asAsync(): AsyncMaterialGenerator<M> = object : AsyncMaterialGenerator<M> {
    override suspend fun generate(): M = this@asAsync.generate()
    override fun generateBlocking(): M = this@asAsync.generate()
}
