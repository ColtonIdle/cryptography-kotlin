package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.provider.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.Apple
)
