/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

private const val ivSize = 12

abstract class AesGcmTest(provider: CryptographyProvider) : AesBasedTest<AES.GCM>(AES.GCM, provider) {
    @Test
    fun testSizes() = runTestForEachKeySize {
        val key = algorithm.asyncKeyGenerator(keySize).generate()
        assertEquals(keySize.value.inBytes, key.asyncEncoder().encodeTo(AES.Key.Format.RAW).size)

        listOf(96, 104, 112, 120, 128).forEach { tagSizeBits ->
            val tagSize = tagSizeBits.bits.inBytes
            key.asyncCipher(tagSizeBits.bits).run {
                listOf(0, 15, 16, 17, 319, 320, 321).forEach { inputSize ->
                    assertEquals(ivSize + inputSize + tagSize, encrypt(ByteArray(inputSize)).size)
                }
            }
        }
    }

    @Test
    fun decryption() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.asyncKeyGenerator(keySize).generate()

        val ciphertext = key.asyncCipher().encrypt(data)
        val plaintext = key.asyncCipher().decrypt(ciphertext)

        assertContentEquals(data, plaintext)
    }

    @Test
    fun decryptionWrongKey() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.asyncKeyGenerator(keySize).generate()
        val wrongKey = algorithm.asyncKeyGenerator(keySize).generate()

        val ciphertext = key.asyncCipher().encrypt(data)

        assertFails { wrongKey.asyncCipher().decrypt(ciphertext) }
    }
}
