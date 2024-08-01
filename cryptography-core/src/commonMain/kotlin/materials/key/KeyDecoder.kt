/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.operations.*

@Deprecated(
    "Replaced by MaterialDecoder and AsyncMaterialDecoder",
    ReplaceWith("AsyncMaterialDecoder<KF, K>", "dev.whyoleg.cryptography.operations.AsyncMaterialDecoder"),
    DeprecationLevel.ERROR
)
public typealias KeyDecoder<KF, K> = AsyncMaterialDecoder<KF, K>
