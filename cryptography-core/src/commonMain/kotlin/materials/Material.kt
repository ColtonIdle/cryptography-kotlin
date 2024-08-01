/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*

// Material could be:
// - key (public/private/secret)
// - key pair
// - certificate
// - parameters

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Material

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialFormat {
    public val name: String
    override fun toString(): String
}
