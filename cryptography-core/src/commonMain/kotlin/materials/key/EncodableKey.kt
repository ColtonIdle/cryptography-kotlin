/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.Key
import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced by 'encoder' and `asyncEncoder` functions",
    level = DeprecationLevel.ERROR
)
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<MF : MaterialFormat> : Key {
    @Deprecated(
        "Replaced with using separate 'asyncEncoder'",
        ReplaceWith("asyncEncoder().encodeTo(format)"),
        level = DeprecationLevel.ERROR
    )
    public suspend fun encodeTo(format: MF): ByteArray = asyncEncoder().encodeTo(format)

    @Deprecated(
        "Replaced with using separate 'encoder'",
        ReplaceWith("encoder().encodeToBlocking(format)"),
        level = DeprecationLevel.ERROR
    )
    public fun encodeToBlocking(format: MF): ByteArray = encoder().encodeTo(format)

    public fun encoder(): MaterialSelfEncoder<MF>
    public fun asyncEncoder(): AsyncMaterialSelfEncoder<MF>
}
