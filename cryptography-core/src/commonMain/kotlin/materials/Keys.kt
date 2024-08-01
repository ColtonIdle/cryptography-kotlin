/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Key : Material

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SymmetricKey : Key

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AsymmetricKey : Key

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PublicKey : AsymmetricKey

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PrivateKey : AsymmetricKey

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyPair : Material {
    public val publicKey: PublicKey
    public val privateKey: PrivateKey
}
