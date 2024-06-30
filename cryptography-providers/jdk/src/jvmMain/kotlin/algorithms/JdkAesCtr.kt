/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import javax.crypto.spec.*

internal class JdkAesCtr(
    private val state: JdkCryptographyState,
) : AES.CTR {
    private val keyWrapper: (JSecretKey) -> AES.CTR.Key = { key ->
        object : AES.CTR.Key, JdkEncodableKey<AES.Key.Format>(key) {
            override fun cipher(): AES.IvCipher = AesCtrCipher(state, key)
            override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
                AES.Key.Format.JWK -> error("$format is not supported")
                AES.Key.Format.RAW -> encodeToRaw()
            }
        }
    }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CTR.Key> = keyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CTR.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.value.inBits, state.secureRandom)
    }
}

private const val ivSizeBytes = 16 //bytes for CTR

private class AesCtrCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.IvCipher {
    private val cipher = state.cipher("AES/CTR/NoPadding")

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray {
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        return iv + encryptBlocking(iv, plaintextInput)
    }

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(plaintextInput)
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(ciphertextInput)
    }
}
