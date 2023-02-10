package dev.whyoleg.cryptography.openssl3.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal abstract class Openssl3PrivateKeyEncodable<KF : KeyFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3KeyEncodable<KF>(key) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    override fun outputStruct(format: KF): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyEncodable<KF : KeyFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3KeyEncodable<KF>(key) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    override fun outputStruct(format: KF): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3KeyEncodable<KF : KeyFormat>(
    protected val key: CPointer<EVP_PKEY>,
) : EncodableKey<KF> {

    protected abstract fun selection(format: KF): Int
    protected abstract fun outputType(format: KF): String
    protected abstract fun outputStruct(format: KF): String

    override fun encodeToBlocking(format: KF): ByteArray = memScoped {
        val context = checkError(
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey = key,
                selection = selection(format),
                output_type = outputType(format).cstr.ptr,
                output_struct = outputStruct(format).cstr.ptr,
                propquery = null
            )
        )
        try {
            //println("PRI_ENCODE: $format")
            val pdataLenVar = alloc<size_tVar>()
            val pdataVar = alloc<CPointerVar<UByteVar>>()
            checkError(OSSL_ENCODER_to_data(context, pdataVar.ptr, pdataLenVar.ptr))
            //println("PRI_ENCODE SIZE[1]: ${pdataLenVar.value}")
            pdataVar.value!!.readBytes(pdataLenVar.value.convert()).also {
                //println("PRI_ENCODE SIZE[2]: ${it.size}")
            }
        } finally {
            OSSL_ENCODER_CTX_free(context)
        }
    }
}
