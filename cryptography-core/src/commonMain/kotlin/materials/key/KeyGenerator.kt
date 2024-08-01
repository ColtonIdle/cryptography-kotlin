/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced by MaterialGenerator and AsyncMaterialGenerator",
    ReplaceWith("AsyncMaterialGenerator<M>", "dev.whyoleg.cryptography.operations.AsyncMaterialGenerator"),
    DeprecationLevel.ERROR
)
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<M : Material> : AsyncMaterialGenerator<M> {
    @Deprecated(
        "Replaced with generate",
        ReplaceWith("generate()"),
        DeprecationLevel.ERROR
    )
    public suspend fun generateKey(): M = generate()

    @Deprecated(
        "Replaced with generateBlocking",
        ReplaceWith("generateBlocking()"),
        DeprecationLevel.ERROR
    )
    public fun generateKeyBlocking(): M = generateBlocking()
}

@Suppress("DEPRECATION_ERROR")
@CryptographyProviderApi
@Deprecated(
    "migration helper",
    level = DeprecationLevel.ERROR
)
public fun <M : Material> MaterialGenerator<M>.asKeyGenerator(): KeyGenerator<M> = object : KeyGenerator<M> {
    override suspend fun generate(): M = this@asKeyGenerator.generate()
    override fun generateBlocking(): M = this@asKeyGenerator.generate()
}
