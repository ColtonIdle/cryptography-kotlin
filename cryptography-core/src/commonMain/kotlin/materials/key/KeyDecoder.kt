/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> {
    // string decoding should only work for PEM and other String formats
    public suspend fun decode(format: KF, input: String): K
    public suspend fun decode(format: KF, input: ByteArray): K
    public suspend fun decode(format: KF, input: ByteString): K

    public fun decodeBlocking(format: KF, input: String): K
    public fun decodeBlocking(format: KF, input: ByteArray): K
    public fun decodeBlocking(format: KF, input: ByteString): K

    @Deprecated("Renamed to decode", ReplaceWith("decode(format, input)"))
    public suspend fun decodeFrom(format: KF, input: ByteArray): K = decode(format, input)

    @Deprecated("Renamed to decodeBlocking", ReplaceWith("decodeBlocking(format, input)"))
    public fun decodeFromBlocking(format: KF, input: ByteArray): K = decodeBlocking(format, input)
}
