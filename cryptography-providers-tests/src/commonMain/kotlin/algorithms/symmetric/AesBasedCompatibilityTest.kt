/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import kotlinx.serialization.*
import kotlin.test.*

abstract class AesBasedCompatibilityTest<K : AES.Key, A : AES<K>>(
    algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : CompatibilityTest<A>(algorithmId, provider) {

    @Serializable
    protected data class KeyParameters(val keySizeBits: Int) : TestParameters

    protected suspend fun CompatibilityTestScope<A>.generateKeys(
        isStressTest: Boolean,
        block: suspend (key: K, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

            val keyParameters = KeyParameters(keySize.value.inBits)
            val keyParametersId = api.keys.saveParameters(keyParameters)
            algorithm.asyncKeyGenerator(keySize).generateMaterials(keyIterations) { key ->
                val keyReference = api.keys.saveData(
                    keyParametersId,
                    KeyData(key.asyncEncoder().encodeTo(AES.Key.Format.entries, ::supportsKeyFormat))
                )
                block(key, keyReference, keyParameters)
            }
        }
    }

    protected suspend fun CompatibilityTestScope<A>.validateKeys() = algorithm.asyncKeyDecoder().let { keyDecoder ->
        buildMap {
            api.keys.getParameters<KeyParameters> { (keySize), parametersId, _ ->
                if (!supportsKeySize(keySize)) return@getParameters

                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = AES.Key.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            AES.Key.Format.RAW -> assertContentEquals(bytes, key.asyncEncoder().encodeTo(format), "Key $format encoding")
                            AES.Key.Format.JWK -> {} //no check for JWK yet
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
    }
}
