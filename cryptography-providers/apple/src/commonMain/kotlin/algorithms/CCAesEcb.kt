/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import platform.CoreCrypto.*

internal object CCAesEcb : CCAes<AES.ECB.Key>(), AES.ECB {
    override fun wrapKey(key: ByteArray): AES.ECB.Key = AesEcbKey(key)

    private class AesEcbKey(private val key: ByteArray) : AES.ECB.Key {
        override fun asyncCipher(padding: Boolean): AsyncCipher = AesEcbCipher(key, padding).asAsync()
        override fun encoder(): MaterialSelfEncoder<AES.Key.Format> = AesKeySelfEncoder(key)
        override fun asyncEncoder(): AsyncMaterialSelfEncoder<AES.Key.Format> = encoder().asAsync()
    }
}

private const val blockSizeBytes = 16 //bytes for ECB

private class AesEcbCipher(key: ByteArray, padding: Boolean) : Cipher {
    private val cipher = CCCipher(
        algorithm = kCCAlgorithmAES,
        mode = kCCModeECB,
        padding = if (padding) ccPKCS7Padding else ccNoPadding,
        key = key
    )

    override fun encrypt(plaintext: ByteArray): ByteArray {
        return cipher.encrypt(null, plaintext)
    }

    override fun decrypt(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return cipher.decrypt(
            iv = null,
            ciphertext = ciphertext,
            ciphertextStartIndex = 0
        )
    }
}
