/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

@Deprecated(
    "Replaced by MaterialFormat",
    ReplaceWith("MaterialFormat", "dev.whyoleg.cryptography.materials.MaterialFormat"),
    DeprecationLevel.ERROR
)
public typealias KeyFormat = dev.whyoleg.cryptography.materials.MaterialFormat
