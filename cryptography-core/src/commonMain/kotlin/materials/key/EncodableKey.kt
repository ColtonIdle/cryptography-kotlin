/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    // string encoding should only work for PEM and other String formats
    public suspend fun encodeToString(format: KF): String
    public suspend fun encodeToByteArray(format: KF): ByteArray
    public suspend fun encodeToByteString(format: KF): ByteString

    public fun encodeToStringBlocking(format: KF): String
    public fun encodeToByteArrayBlocking(format: KF): ByteArray
    public fun encodeToByteStringBlocking(format: KF): ByteString

    @Deprecated("Renamed to encodeToByteArray", ReplaceWith("encodeToByteArray(format)"))
    public suspend fun encodeTo(format: KF): ByteArray = encodeToByteArray(format)

    @Deprecated("Renamed to encodeToByteArrayBlocking", ReplaceWith("encodeToByteArrayBlocking(format)"))
    public fun encodeToBlocking(format: KF): ByteArray = encodeToByteArrayBlocking(format)
}
