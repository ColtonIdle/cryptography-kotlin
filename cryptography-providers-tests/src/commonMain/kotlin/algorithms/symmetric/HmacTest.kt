/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlin.math.*
import kotlin.test.*

abstract class HmacTest(provider: CryptographyProvider) : ProviderTest(provider) {

    private class HmacTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: HMAC,
        val digest: CryptographyAlgorithmId<Digest>,
        val digestSize: Int,
        val digestBlockSize: Int,
    ) : AlgorithmTestScope<HMAC>(logger, context, provider, algorithm)

    private fun runTestForEachDigest(block: suspend HmacTestScope.() -> Unit) = testAlgorithm(HMAC) {
        //all values are in bytes
        listOf(
            Triple(SHA1, 20, 64),
            Triple(SHA224, 28, 64),
            Triple(SHA256, 32, 64),
            Triple(SHA384, 48, 128),
            Triple(SHA512, 64, 128),
            Triple(SHA3_224, 28, 144),
            Triple(SHA3_256, 32, 136),
            Triple(SHA3_384, 48, 104),
            Triple(SHA3_512, 64, 72),
        ).forEach { (digest, digestSize, digestBlockSize) ->
            if (!supportsDigest(digest)) return@forEach

            block(HmacTestScope(logger, context, provider, algorithm, digest, digestSize, digestBlockSize))
        }
    }

    @Test
    fun testSizes() = runTestForEachDigest {
        val key = algorithm.asyncKeyGenerator(digest).generate()
        assertEquals(digestBlockSize, key.asyncEncoder().encodeTo(HMAC.Key.Format.RAW).size)
        val signatureGenerator = key.asyncSignatureGenerator()

        assertEquals(digestSize, signatureGenerator.generateSignature(ByteArray(0)).size)
        repeat(8) { n ->
            val size = 10.0.pow(n).toInt()
            val data = CryptographyRandom.nextBytes(size)
            assertEquals(digestSize, signatureGenerator.generateSignature(data).size)
        }
    }

    @Test
    fun verifyNoFail() = runTestForEachDigest {
        val key = algorithm.asyncKeyGenerator(digest).generate()
        assertFalse(key.asyncSignatureVerifier().verifySignature(ByteArray(0), ByteArray(0)))
        assertFalse(key.asyncSignatureVerifier().verifySignature(ByteArray(10), ByteArray(0)))
        assertFalse(key.asyncSignatureVerifier().verifySignature(ByteArray(10), ByteArray(10)))
    }

    @Test
    fun verifyResult() = runTestForEachDigest {
        val key = algorithm.asyncKeyGenerator(digest).generate()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.asyncSignatureGenerator().generateSignature(data)
        assertTrue(key.asyncSignatureVerifier().verifySignature(data, signature))
    }

    @Test
    fun verifyResultWrongKey() = runTestForEachDigest {
        val keyGenerator = algorithm.asyncKeyGenerator(digest)
        val key = keyGenerator.generate()
        val wrongKey = keyGenerator.generate()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.asyncSignatureGenerator().generateSignature(data)
        assertFalse(wrongKey.asyncSignatureVerifier().verifySignature(data, signature))
    }
}
