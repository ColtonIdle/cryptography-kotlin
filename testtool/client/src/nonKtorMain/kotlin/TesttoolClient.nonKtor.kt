/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.client

import kotlinx.coroutines.flow.*

internal actual suspend fun postData(path: String, bytes: ByteArray): String {
    TODO("Not yet implemented")
}

internal actual fun getData(path: String): Flow<Pair<String, ByteArray>> {
    TODO("Not yet implemented")
}
