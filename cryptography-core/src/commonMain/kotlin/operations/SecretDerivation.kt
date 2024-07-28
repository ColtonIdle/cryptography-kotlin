/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation<K : Key> {
    public fun deriveSecret(other: K): ByteArray
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsyncSecretDerivation<K : Key> {
    public suspend fun deriveSecret(other: K): ByteArray
}

@CryptographyProviderApi
public fun <K : Key> SecretDerivation<K>.asAsync(): AsyncSecretDerivation<K> = object : AsyncSecretDerivation<K> {
    override suspend fun deriveSecret(other: K): ByteArray = this@asAsync.deriveSecret(other)
}
