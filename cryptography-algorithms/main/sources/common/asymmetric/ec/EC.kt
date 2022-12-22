package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import kotlin.jvm.*

//ECDSA and ECDH
public class EC(
    keyPairGeneratorProvider: KeyGeneratorProvider<KeyPairGeneratorParameters, KeyPair>,
) : CryptographyAlgorithm {
    public companion object : CryptographyAlgorithmIdentifier<EC> //EC

    public val keyPairGenerator: KeyGeneratorFactory<KeyPairGeneratorParameters, KeyPair> = keyPairGeneratorProvider.factory(
        operationId = CryptographyOperationId("EC"),
        defaultParameters = KeyPairGeneratorParameters.Default,
    )

    public class KeyPair(
        public val publicKey: PublicKey,
        public val privateKey: PrivateKey,
    )

    public class PublicKey(
        verifierProvider: VerifierProvider<SignatureParameters>,
        keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
    ) {
        public val verifier: VerifierFactory<SignatureParameters> = verifierProvider.factory(
            operationId = CryptographyOperationId("ECDSA"),
            defaultParameters = SignatureParameters.Default,
        )
        public val encoder: KeyEncoderFactory<CryptographyParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("EC"),
            defaultParameters = CryptographyParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    //TODO: Decide on how to get PublicKey from PrivateKey
    public class PrivateKey(
        signerProvider: SignerProvider<SignatureParameters>,
        keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
    ) {
        public val verifier: SignerFactory<SignatureParameters> = signerProvider.factory(
            operationId = CryptographyOperationId("ECDSA"),
            defaultParameters = SignatureParameters.Default,
        )
        public val encoder: KeyEncoderFactory<CryptographyParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("EC"),
            defaultParameters = CryptographyParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class KeyPairGeneratorParameters(
        public val curve: Curve = Curve.P521, //TODO: default curve?
    ) : CryptographyParameters {
        public companion object {
            public val Default: KeyPairGeneratorParameters = KeyPairGeneratorParameters()
        }
    }

    //TODO: drop generics and enforce it's contract via custom constructor?
    public class SignatureParameters(
        public val digest: CryptographyAlgorithmIdentifier<Digest> = SHA512,
    ) : CryptographyParameters {
        public companion object {
            public val Default: SignatureParameters = SignatureParameters()
        }
    }


    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P521: Curve get() = Curve("P521")
            public val P384: Curve get() = Curve("P384")
            public val P256: Curve get() = Curve("P256")

            //Curve25519 should be separate
//        public val Curve25519: ECCurve get() = ECCurve("Curve25519")
        }
    }
}

//private fun test() {
//    val key1 = engine.get(EC).keyGenerator().generateKey()
//    val key2 = engine.get(EC).keyGenerator().generateKey()
//
//    val encoded1 = key1.public.encode(format)
//    val encoded2 = key2.public.encode(format)
//
//    key1.private.keyAgreement().agreeKey(format, encoded2)
//}
