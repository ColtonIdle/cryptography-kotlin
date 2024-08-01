/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.random.*
import platform.CoreCrypto.*

internal object CCAesCbc : CCAes<AES.CBC.Key>(), AES.CBC {
    override fun wrapKey(key: ByteArray): AES.CBC.Key = AesCbcKey(key)

    private class AesCbcKey(private val key: ByteArray) : AES.CBC.Key {
        override fun asyncCipher(padding: Boolean): AES.AsyncIvCipher = AesCbcCipher(key, padding).asAsync()
        override fun encoder(): MaterialSelfEncoder<AES.Key.Format> = AesKeySelfEncoder(key)
        override fun asyncEncoder(): AsyncMaterialSelfEncoder<AES.Key.Format> = encoder().asAsync()
    }
}

private const val ivSizeBytes = 16 //bytes for CBC
private const val blockSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(key: ByteArray, padding: Boolean) : AES.IvCipher {
    private val cipher = CCCipher(
        algorithm = kCCAlgorithmAES,
        mode = kCCModeCBC,
        padding = if (padding) ccPKCS7Padding else ccNoPadding,
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
        require(ciphertext.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return cipher.decrypt(
            iv = ciphertext,
            ciphertext = ciphertext,
            ciphertextStartIndex = ivSizeBytes
        )
    }

    @DelicateCryptographyApi
    override fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }
        require(ciphertext.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return cipher.decrypt(
            iv = iv,
            ciphertext = ciphertext,
            ciphertextStartIndex = 0
        )
    }
}
