/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*

@Suppress("DEPRECATION_ERROR")
internal abstract class CCAes<K : AES.Key> : AES<K> {
    protected abstract fun wrapKey(key: ByteArray): K

    final override fun asyncKeyDecoder(): AsyncMaterialDecoder<AES.Key.Format, K> = AesKeyDecoder().asAsync()

    final override fun asyncKeyGenerator(keySize: SymmetricKeySize): KeyGenerator<K> =
        AesCtrKeyGenerator(keySize.value.inBytes).asKeyGenerator()

    private inner class AesKeyDecoder : MaterialDecoder<AES.Key.Format, K> {
        override fun decodeFrom(format: AES.Key.Format, data: ByteArray): K = when (format) {
            AES.Key.Format.RAW -> {
                require(data.size == 16 || data.size == 24 || data.size == 32) {
                    "AES key size must be 128, 192 or 256 bits"
                }
                wrapKey(data.copyOf())
            }
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    protected class AesKeySelfEncoder(private val key: ByteArray) : MaterialSelfEncoder<AES.Key.Format> {
        override fun encodeTo(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    private inner class AesCtrKeyGenerator(private val keySizeBytes: Int) : MaterialGenerator<K> {
        override fun generate(): K {
            val key = CryptographyRandom.nextBytes(keySizeBytes)
            return wrapKey(key)
        }
    }
}
