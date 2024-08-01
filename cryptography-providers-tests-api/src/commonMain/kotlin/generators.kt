/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

inline fun generateSymmetricKeySize(block: (keySize: SymmetricKeySize) -> Unit) {
    generate(block, SymmetricKeySize.B128, SymmetricKeySize.B192, SymmetricKeySize.B256)
}

inline fun generateRsaKeySizes(block: (keySize: BinarySize) -> Unit) {
    generate(block, 2048.bits, 3072.bits, 4096.bits)
}

inline fun generateDigests(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
    listOf(
        SHA1 to 20,
        SHA224 to 28,
        SHA256 to 32,
        SHA384 to 48,
        SHA512 to 64,
        SHA3_224 to 28,
        SHA3_256 to 32,
        SHA3_384 to 48,
        SHA3_512 to 64,
    ).forEach { block(it.first, it.second) }
}

// workaround for now to reduce data for compatibility tests
inline fun generateDigestsForCompatibility(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
    listOf(
        SHA1 to 20,
        SHA256 to 32,
        SHA512 to 64,
        SHA3_256 to 32,
        SHA3_512 to 64,
    ).forEach { block(it.first, it.second) }
}

suspend inline fun <M : Material> AsyncMaterialGenerator<M>.generateMaterials(count: Int, block: (key: M) -> Unit) {
    repeat(count) { block(generate()) }
}

inline fun <T> generate(block: (value: T) -> Unit, vararg values: T) {
    values.forEach { block(it) }
}

inline fun generateBoolean(block: (value: Boolean) -> Unit) {
    generate(block, true, false)
}
