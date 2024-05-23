/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = """
              This is an API which should be used only for providing support for additional cryptography implementations.
              This API is subject to change, if possible in backward-compatible way.
              """
)
public annotation class CryptographyProviderApi

@RequiresOptIn(
    level = RequiresOptIn.Level.WARNING,
    message = """This is an experimental API for integration with kotlinx-io."""
)
public annotation class ExperimentalCryptographyIoApi


// The difference between LegacyCryptography and DelicateCryptographyApi is
// that `LegacyCryptography` is more about legacy algorithms (such as MD5, SHA1 or AES-ECB);
// while `DelicateCryptographyApi` is more about operations which should be done with care (f.e providing custom IV)

@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = """
              API marked with this annotation should be used only when you know what you are doing.
              Avoid usage of such declarations as much as possible.
              They are provided mostly for backward compatibility with older services that require them.
              """
)
public annotation class DelicateCryptographyApi

@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = """
              API marked with this annotation should be used only when you know what you are doing.
              Avoid usage of such declarations as much as possible.
              They are provided mostly for backward compatibility with older services that require them.
              """
)
public annotation class LegacyCryptography
