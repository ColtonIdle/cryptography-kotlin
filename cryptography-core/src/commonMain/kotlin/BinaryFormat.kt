/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

public interface BinaryFormat {
    public val name: String
    override fun toString(): String

    // RAW
    // JWK
    // DER
    // PEM
    // PKCS12?
}

public interface BinaryCodec<F : BinaryFormat, D> : BinaryDecoder<F, D>, BinaryEncoder<F, D>

public interface BinaryDecoder<F : BinaryFormat, D> {
    public fun decodeTo(format: F, data: BinaryData): D
}

public interface BinaryEncoder<F : BinaryFormat, D> {
    public fun encodeTo(format: F, data: D): BinaryData
}

public interface BinarySelfEncoder<F : BinaryFormat> {
    public fun encodeTo(format: F): BinaryData
}

public interface AsyncBinaryCodec<F : BinaryFormat, D> : AsyncBinaryDecoder<F, D>, AsyncBinaryEncoder<F, D>

public interface AsyncBinaryDecoder<F : BinaryFormat, D> {
    public suspend fun decodeTo(format: F, data: BinaryData): D
}

public interface AsyncBinaryEncoder<F : BinaryFormat, D> {
    public suspend fun encodeTo(format: F, data: D): BinaryData
}

public interface AsyncBinarySelfEncoder<F : BinaryFormat> {
    public suspend fun encodeTo(format: F): BinaryData
}
