/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

@Suppress("DEPRECATION_ERROR")
internal abstract class WebCryptoEncodableKey<KF : MaterialFormat>(
    private val key: CryptoKey,
    private val keyProcessor: WebCryptoKeyProcessor<KF>,
) : EncodableKey<KF> {
    override fun encoder(): MaterialSelfEncoder<KF> = nonBlocking()

    override fun asyncEncoder(): AsyncMaterialSelfEncoder<KF> = object : AsyncMaterialSelfEncoder<KF> {
        override suspend fun encodeTo(format: KF): ByteArray = keyProcessor.afterEncoding(
            format = format,
            key = WebCrypto.exportKey(keyProcessor.stringFormat(format), key)
        )
    }
}
