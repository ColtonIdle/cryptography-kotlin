/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.support.*
import kotlin.test.*

class SupportedAlgorithmsTest {

    private fun ProviderTestContext.assertSupports(
        algorithmId: CryptographyAlgorithmId<*>,
        supported: Boolean = true,
    ) {
        val algorithm = provider.getOrNull(algorithmId)
        when {
            supported -> assertNotNull(algorithm, "Algorithm ${algorithmId.name} is not supported by ${provider.name} provider")
            else      -> assertNull(algorithm, "Algorithm ${algorithmId.name} is supported by ${provider.name} provider")
        }
    }

    @Test
    fun testSupported() = runTestForEachProvider {
        assertSupports(AES.CBC)
        assertSupports(AES.GCM, !provider.isApple)

        assertSupports(HMAC)

        assertSupports(MD5, !provider.isWebCrypto)
        assertSupports(SHA1)
        assertSupports(SHA256)
        assertSupports(SHA384)
        assertSupports(SHA512)

        assertSupports(ECDSA, !provider.isApple)

        assertSupports(RSA.PSS, !provider.isApple)
        assertSupports(RSA.OAEP, !provider.isApple)
        assertSupports(RSA.PKCS1, !provider.isApple)
    }
}