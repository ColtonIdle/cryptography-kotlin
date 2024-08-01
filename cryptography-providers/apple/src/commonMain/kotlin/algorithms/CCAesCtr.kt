/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCAesCtr : CCAes<AES.CTR.Key>(), AES.CTR {
    override fun wrapKey(key: ByteArray): AES.CTR.Key = AesCtrKey(key)

    private class AesCtrKey(private val key: ByteArray) : AES.CTR.Key {
        override fun asyncCipher(): AES.AsyncIvCipher = AesCtrCipher(key).asAsync()
        override fun encoder(): MaterialSelfEncoder<AES.Key.Format> = AesKeySelfEncoder(key)
        override fun asyncEncoder(): AsyncMaterialSelfEncoder<AES.Key.Format> = encoder().asAsync()
    }
}

private const val ivSizeBytes = 16 //bytes for CTR

private class AesCtrCipher(key: ByteArray) : AES.IvCipher {
    private val cipher = CCCipher(
        algorithm = kCCAlgorithmAES,
        mode = kCCModeCTR,
        padding = 0.convert(), // not applicable
        key = key
    )

    override fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)
        return iv + encrypt(iv, plaintext)
    }

    @DelicateCryptographyApi
    override fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return cipher.encrypt(iv, plaintext)
    }

    override fun decrypt(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size >= ivSizeBytes) { "Ciphertext is too short" }

        return cipher.decrypt(
            iv = ciphertext,
            ciphertext = ciphertext,
            ciphertextStartIndex = ivSizeBytes
        )
    }

    @DelicateCryptographyApi
    override fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return cipher.decrypt(
            iv = iv,
            ciphertext = ciphertext,
            ciphertextStartIndex = 0
        )
    }
}
