/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*

internal abstract class Openssl3Aes<K : AES.Key> : AES<K> {

    protected abstract fun wrapKey(keySize: SymmetricKeySize, key: ByteArray): K

    private val keyDecoder = AesKeyDecoder().asAsync()
    final override fun asyncKeyDecoder(): AsyncMaterialDecoder<AES.Key.Format, K> = keyDecoder

    @Suppress("DEPRECATION_ERROR")
    final override fun asyncKeyGenerator(keySize: SymmetricKeySize): KeyGenerator<K> = AesKeyGenerator(keySize).asKeyGenerator()

    private fun requireAesKeySize(keySize: SymmetricKeySize) {
        require(keySize == SymmetricKeySize.B128 || keySize == SymmetricKeySize.B192 || keySize == SymmetricKeySize.B256) {
            "AES key size must be 128, 192 or 256 bits"
        }
    }

    private inner class AesKeyDecoder : MaterialDecoder<AES.Key.Format, K> {
        override fun decodeFrom(format: AES.Key.Format, data: ByteArray): K = when (format) {
            AES.Key.Format.RAW -> {
                val keySize = SymmetricKeySize(data.size.bytes)
                requireAesKeySize(keySize)
                wrapKey(keySize, data.copyOf())
            }
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    private inner class AesKeyGenerator(
        private val keySize: SymmetricKeySize,
    ) : MaterialGenerator<K> {

        init {
            requireAesKeySize(keySize)
        }

        override fun generate(): K {
            val key = CryptographyRandom.nextBytes(keySize.value.inBytes)
            return wrapKey(keySize, key)
        }
    }

    protected abstract class AesKey(
        protected val key: ByteArray,
    ) : AES.Key {
        override fun asyncEncoder(): AsyncMaterialSelfEncoder<AES.Key.Format> = encoder().asAsync()
        override fun encoder(): MaterialSelfEncoder<AES.Key.Format> = object : MaterialSelfEncoder<AES.Key.Format> {
            override fun encodeTo(format: AES.Key.Format): ByteArray = when (format) {
                AES.Key.Format.RAW -> key.copyOf()
                AES.Key.Format.JWK -> error("JWK is not supported")
            }
        }
    }
}
