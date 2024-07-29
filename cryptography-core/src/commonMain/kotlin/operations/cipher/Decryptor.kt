/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced with AsyncDecryptor",
    ReplaceWith("AsyncDecryptor", "dev.whyoleg.cryptography.operations.AsyncDecryptor"),
    DeprecationLevel.ERROR
)
public typealias Decryptor = AsyncDecryptor
