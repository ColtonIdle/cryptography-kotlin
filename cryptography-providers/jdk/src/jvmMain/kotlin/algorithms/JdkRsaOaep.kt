/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import java.security.spec.*
import javax.crypto.spec.*

internal class JdkRsaOaep(
    private val state: JdkCryptographyState,
) : RSA.OAEP {

    override fun asyncPublicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> =
        RsaOaepPublicKeyDecoder(state, digest.rsaHashAlgorithmName()).asAsync()

    override fun asyncPrivateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): AsyncMaterialDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        RsaOaepPrivateKeyDecoder(state, digest.rsaHashAlgorithmName()).asAsync()

    @Suppress("DEPRECATION_ERROR")
    override fun asyncKeyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.OAEP.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaOaepKeyPairGenerator(state, rsaParameters, digest.rsaHashAlgorithmName()).asKeyGenerator()
    }
}

private class RsaOaepPublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPublicKeyDecoder<RSA.OAEP.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.OAEP.PublicKey {
        return RsaOaepPublicKey(state, this, hashAlgorithmName)
    }
}

private class RsaOaepPrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPrivateKeyDecoder<RSA.OAEP.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.OAEP.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.OAEP.KeyPair = RsaOaepKeyPair(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.OAEP.KeyPair {
    override val publicKey: RSA.OAEP.PublicKey = RsaOaepPublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaOaepPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PublicKey, RsaPublicEncodableKey(key) {
    private val encryptor = RsaOaepEncryptor(state, key, hashAlgorithmName).asAsync()
    override fun asyncEncryptor(): AsyncAuthenticatedEncryptor = encryptor
}

private class RsaOaepPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PrivateKey, RsaPrivateEncodableKey(key) {
    private val decryptor = RsaOaepDecryptor(state, key, hashAlgorithmName).asAsync()
    override fun asyncDecryptor(): AsyncAuthenticatedDecryptor = decryptor
}

private class RsaOaepEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : AuthenticatedEncryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = cipher.use { cipher ->
        val parameters = OAEPParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec(hashAlgorithmName),
            associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
        )
        cipher.init(JCipher.ENCRYPT_MODE, key, parameters, state.secureRandom)
        cipher.doFinal(plaintext)
    }
}

private class RsaOaepDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : AuthenticatedDecryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = cipher.use { cipher ->
        val parameters = OAEPParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec(hashAlgorithmName),
            associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
        )
        cipher.init(JCipher.DECRYPT_MODE, key, parameters, state.secureRandom)
        cipher.doFinal(ciphertext)
    }
}
