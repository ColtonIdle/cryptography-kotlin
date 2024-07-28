/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced with AsyncHasher",
    ReplaceWith("AsyncHasher", "dev.whyoleg.cryptography.operations.AsyncHasher"),
    DeprecationLevel.ERROR
)
public typealias Hasher = AsyncHasher
