/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced with AsyncSignatureGenerator",
    ReplaceWith("AsyncSignatureGenerator", "dev.whyoleg.cryptography.operations.AsyncSignatureGenerator"),
    DeprecationLevel.ERROR
)
public typealias SignatureGenerator = AsyncSignatureGenerator
