/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

public open class CryptographyException : RuntimeException {
    public constructor(message: String?) : super(message)
    public constructor(message: String?, cause: Throwable?) : super(message, cause)
    public constructor(cause: Throwable?) : super(cause)
}

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmId<*>,
) : CryptographyException("Algorithm not found: $algorithm")
