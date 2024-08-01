/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.*

import dev.whyoleg.cryptography.operations.*
import kotlin.test.*

suspend fun <MF : MaterialFormat> AsyncMaterialSelfEncoder<MF>.encodeTo(
    formats: Collection<MF>,
    supports: (MF) -> Boolean,
): Map<String, ByteArray> = formats.filter(supports).associate {
    it.name to encodeTo(it)
}.also {
    assertTrue(it.isNotEmpty(), "No supported formats")
}

suspend inline fun <MF : MaterialFormat, M : Material> AsyncMaterialDecoder<MF, M>.decodeFrom(
    formats: Map<String, ByteArray>,
    formatOf: (String) -> MF,
    supports: (MF) -> Boolean,
    supportsDecoding: (MF, ByteArray) -> Boolean = { _, _ -> true },
    validate: (material: M, format: MF, bytes: ByteArray) -> Unit,
): List<M> {
    val supportedFormats = formats
        .mapKeys { (formatName, _) -> formatOf(formatName) }
        .filterKeys(supports)

    val materials = supportedFormats.mapNotNull {
        if (supportsDecoding(it.key, it.value)) decodeFrom(it.key, it.value) else null
    }

    materials.forEach { material ->
        supportedFormats.forEach { (format, bytes) ->
            validate(material, format, bytes)
        }
    }

    return materials
}

fun digest(name: String): CryptographyAlgorithmId<Digest> = when (name) {
    MD5.name      -> MD5
    SHA1.name     -> SHA1
    SHA224.name   -> SHA224
    SHA256.name   -> SHA256
    SHA384.name   -> SHA384
    SHA512.name   -> SHA512
    SHA3_224.name -> SHA3_224
    SHA3_256.name -> SHA3_256
    SHA3_384.name -> SHA3_384
    SHA3_512.name -> SHA3_512
    else          -> error("Unknown digest: $name")
}

expect fun disableJsConsoleDebug()

// Wasm tests on browser cannot be filtered: https://youtrack.jetbrains.com/issue/KT-58291
@OptIn(ExperimentalMultiplatform::class)
@OptionalExpectation
expect annotation class WasmIgnore()
