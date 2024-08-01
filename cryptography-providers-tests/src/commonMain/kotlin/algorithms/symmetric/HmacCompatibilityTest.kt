/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.serialization.*
import kotlin.test.*

private const val maxDataSize = 10000

abstract class HmacCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<HMAC>(HMAC, provider) {

    @Serializable
    private data class KeyParameters(val digestName: String) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<HMAC>.generate(isStressTest: Boolean) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val dataIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        generateDigests { digest, _ ->
            if (!supportsDigest(digest)) return@generateDigests

            val keyParametersId = api.keys.saveParameters(KeyParameters(digest.name))
            algorithm.asyncKeyGenerator(digest).generateMaterials(keyIterations) { key ->
                val keyReference = api.keys.saveData(
                    keyParametersId,
                    KeyData(key.asyncEncoder().encodeTo(HMAC.Key.Format.entries, ::supportsKeyFormat))
                )

                val signatureGenerator = key.asyncSignatureGenerator()
                val signatureVerifier = key.asyncSignatureVerifier()
                repeat(dataIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logger.log { "data.size      = $dataSize" }
                    val data = CryptographyRandom.nextBytes(dataSize)
                    val signature = signatureGenerator.generateSignature(data)
                    logger.log { "signature.size = ${signature.size}" }

                    assertTrue(signatureVerifier.verifySignature(data, signature), "Initial Verify")

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    override suspend fun CompatibilityTestScope<HMAC>.validate() {
        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { parameters, parametersId, _ ->
                if (!supportsDigest(parameters.digest)) return@getParameters

                val keyDecoder = algorithm.asyncKeyDecoder(parameters.digest)
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = HMAC.Key.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            HMAC.Key.Format.RAW -> assertContentEquals(bytes, key.asyncEncoder().encodeTo(format), "Key $format encoding")
                            HMAC.Key.Format.JWK -> {} //no check for JWK yet
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val verifier = key.asyncSignatureVerifier()
                    val generator = key.asyncSignatureGenerator()

                    assertTrue(verifier.verifySignature(data, signature), "Verify")
                    assertTrue(verifier.verifySignature(data, generator.generateSignature(data)), "Sign-Verify")
                }
            }
        }
    }
}
