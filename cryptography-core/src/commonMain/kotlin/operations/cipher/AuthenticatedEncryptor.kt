/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced with AsyncAuthenticatedEncryptor",
    ReplaceWith("AsyncAuthenticatedEncryptor", "dev.whyoleg.cryptography.operations.AsyncAuthenticatedEncryptor"),
    DeprecationLevel.ERROR
)
public typealias AuthenticatedEncryptor = AsyncAuthenticatedEncryptor
