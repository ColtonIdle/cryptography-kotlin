/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    public fun keyDecoder(): KeyDecoder<Key.Format, K>
    public fun keyGenerator(keySize: SymmetricKeySize = SymmetricKeySize.B256): KeyGenerator<K>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public enum class Format : KeyFormat { RAW, JWK }
    }

    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface ECB : AES<ECB.Key> {
        override val id: CryptographyAlgorithmId<ECB> get() = Companion

        public companion object : CryptographyAlgorithmId<ECB>("AES-ECB")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            @Deprecated(
                "Renamed to asyncCipher",
                ReplaceWith("asyncCipher(padding)"),
                DeprecationLevel.ERROR
            )
            public fun cipher(padding: Boolean = true): AsyncCipher = asyncCipher(padding)
            public fun asyncCipher(padding: Boolean = true): AsyncCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CBC : AES<CBC.Key> {
        override val id: CryptographyAlgorithmId<CBC> get() = Companion

        public companion object : CryptographyAlgorithmId<CBC>("AES-CBC")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            @Deprecated(
                "Renamed to asyncCipher",
                ReplaceWith("asyncCipher(padding)"),
                DeprecationLevel.ERROR
            )
            public fun cipher(padding: Boolean = true): AsyncIvCipher = asyncCipher(padding)
            public fun asyncCipher(padding: Boolean = true): AsyncIvCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CTR : AES<CTR.Key> {
        override val id: CryptographyAlgorithmId<CTR> get() = Companion

        public companion object : CryptographyAlgorithmId<CTR>("AES-CTR")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            @Deprecated(
                "Renamed to asyncCipher",
                ReplaceWith("asyncCipher()"),
                DeprecationLevel.ERROR
            )
            public fun cipher(): AsyncIvCipher = asyncCipher()
            public fun asyncCipher(): AsyncIvCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface GCM : AES<GCM.Key> {
        override val id: CryptographyAlgorithmId<GCM> get() = Companion

        public companion object : CryptographyAlgorithmId<GCM>("AES-GCM")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            @Deprecated(
                "Renamed to asyncCipher",
                ReplaceWith("asyncCipher(tagSize)"),
                DeprecationLevel.ERROR
            )
            public fun cipher(tagSize: BinarySize = 128.bits): AsyncAuthenticatedCipher = asyncCipher(tagSize)
            public fun asyncCipher(tagSize: BinarySize = 128.bits): AsyncAuthenticatedCipher
        }
    }

    // not used until 0.5.0
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvCipher : IvEncryptor, IvDecryptor

    // not used until 0.5.0
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvEncryptor : Encryptor {
        @DelicateCryptographyApi
        public fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray
    }

    // not used until 0.5.0
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvDecryptor : Decryptor {
        @DelicateCryptographyApi
        public fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface AsyncIvCipher : AsyncIvEncryptor, AsyncIvDecryptor

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface AsyncIvEncryptor : AsyncEncryptor {
        @DelicateCryptographyApi
        public suspend fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray

        // will be deprecated in 0.5.0
        @DelicateCryptographyApi
        public fun encryptBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface AsyncIvDecryptor : AsyncDecryptor {
        @DelicateCryptographyApi
        public suspend fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray

        // will be deprecated in 0.5.0
        @DelicateCryptographyApi
        public fun decryptBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray
    }
}

@CryptographyProviderApi
public fun AES.IvEncryptor.asAsync(): AES.AsyncIvEncryptor = object : AES.AsyncIvEncryptor {
    override suspend fun encrypt(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)

    @DelicateCryptographyApi
    override suspend fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray = this@asAsync.encrypt(iv, plaintext)

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray = this@asAsync.encrypt(iv, plaintext)
}

@CryptographyProviderApi
public fun AES.IvDecryptor.asAsync(): AES.AsyncIvDecryptor = object : AES.AsyncIvDecryptor {
    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)

    @DelicateCryptographyApi
    override suspend fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(iv, ciphertext)

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(iv, ciphertext)
}

@CryptographyProviderApi
public fun AES.IvCipher.asAsync(): AES.AsyncIvCipher = object : AES.AsyncIvCipher {
    override suspend fun encrypt(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = this@asAsync.encrypt(plaintext)

    @DelicateCryptographyApi
    override suspend fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray = this@asAsync.encrypt(iv, plaintext)

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray = this@asAsync.encrypt(iv, plaintext)

    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(ciphertext)

    @DelicateCryptographyApi
    override suspend fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(iv, ciphertext)

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray = this@asAsync.decrypt(iv, ciphertext)
}
