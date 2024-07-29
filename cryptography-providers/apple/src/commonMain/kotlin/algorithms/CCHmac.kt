/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCHmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        return when (digest) {
            SHA1   -> HmacKeyDecoder(kCCHmacAlgSHA1, CC_SHA1_BLOCK_BYTES, CC_SHA1_DIGEST_LENGTH)
            SHA224 -> HmacKeyDecoder(kCCHmacAlgSHA224, CC_SHA224_BLOCK_BYTES, CC_SHA224_DIGEST_LENGTH)
            SHA256 -> HmacKeyDecoder(kCCHmacAlgSHA256, CC_SHA256_BLOCK_BYTES, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyDecoder(kCCHmacAlgSHA384, CC_SHA384_BLOCK_BYTES, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyDecoder(kCCHmacAlgSHA512, CC_SHA512_BLOCK_BYTES, CC_SHA512_DIGEST_LENGTH)
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        return when (digest) {
            SHA1   -> HmacKeyGenerator(kCCHmacAlgSHA1, CC_SHA1_BLOCK_BYTES, CC_SHA1_DIGEST_LENGTH)
            SHA224 -> HmacKeyGenerator(kCCHmacAlgSHA224, CC_SHA224_BLOCK_BYTES, CC_SHA224_DIGEST_LENGTH)
            SHA256 -> HmacKeyGenerator(kCCHmacAlgSHA256, CC_SHA256_BLOCK_BYTES, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyGenerator(kCCHmacAlgSHA384, CC_SHA384_BLOCK_BYTES, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyGenerator(kCCHmacAlgSHA512, CC_SHA512_BLOCK_BYTES, CC_SHA512_DIGEST_LENGTH)
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
    }
}

private class HmacKeyDecoder(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val keySizeBytes: Int,
    private val digestSize: Int,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromBlocking(format: HMAC.Key.Format, input: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> {
            require(input.size == keySizeBytes) { "Invalid key size: ${input.size}, expected: $keySizeBytes" }
            HmacKey(hmacAlgorithm, input.copyOf(), digestSize)
        }
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacKeyGenerator(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val keySizeBytes: Int,
    private val digestSize: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return HmacKey(hmacAlgorithm, key, digestSize)
    }
}

private class HmacKey(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val key: ByteArray,
    private val digestSize: Int,
) : HMAC.Key, SignatureGenerator, SignatureVerifier {
    override fun asyncSignatureGenerator(): AsyncSignatureGenerator = (this as SignatureGenerator).asAsync()
    override fun asyncSignatureVerifier(): AsyncSignatureVerifier = (this as SignatureVerifier).asAsync()

    override fun encodeToBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }

    override fun generateSignature(dataInput: ByteArray): ByteArray {
        val macOutput = ByteArray(digestSize)
        @OptIn(UnsafeNumber::class)
        CCHmac(
            algorithm = hmacAlgorithm,
            key = key.refTo(0),
            keyLength = key.size.convert(),
            data = dataInput.fixEmpty().refTo(0),
            dataLength = dataInput.size.convert(),
            macOut = macOutput.refTo(0)
        )
        return macOutput
    }

    override fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return generateSignature(dataInput).contentEquals(signatureInput)
    }
}
