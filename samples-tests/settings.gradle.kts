/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

rootProject.name = "samples-tests"

includeBuild("../") {
    name = "cryptography-kotlin"
}
includeBuild("../samples") {
    name = "samples"
}
