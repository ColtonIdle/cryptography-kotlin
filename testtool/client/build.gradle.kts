/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    alias(kotlinLibs.plugins.multiplatform)
}

kotlin {
    explicitApi()

    jvmToolchain(8)

    jvm()
    js(IR) {
        nodejs()
        browser()
    }

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    watchosX64()
    watchosArm32()
    watchosArm64()
    watchosSimulatorArm64()

    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()

    macosX64()
    macosArm64()

    linuxX64()
    linuxArm64()
    mingwX64()

    // No support from KTOR
    watchosDeviceArm64()
    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                withJs()
                withWasm()
                withNative()
            }
            group("ktor") {
                withCompilations {
                    val target = (it.target as? KotlinNativeTarget)?.konanTarget
                    when {
                        target == KonanTarget.WATCHOS_DEVICE_ARM64 -> false
                        target?.family == Family.ANDROID           -> false
                        else                                       -> true
                    }
                }
            }
            group("nonKtor") {
                withCompilations {
                    val target = (it.target as? KotlinNativeTarget)?.konanTarget
                    when {
                        target == KonanTarget.WATCHOS_DEVICE_ARM64 -> true
                        target?.family == Family.ANDROID           -> true
                        else                                       -> false
                    }
                }
            }
            group("cio") {
                withCompilations {
                    val target = (it.target as? KotlinNativeTarget)?.konanTarget
                    when {
                        target == KonanTarget.WATCHOS_DEVICE_ARM64 -> false
                        target?.family?.isAppleFamily == true      -> true
                        target?.family == Family.LINUX             -> true
                        else                                       -> false
                    }
                }
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.api)
            }
        }
        val ktorMain by getting {
            dependencies {
                implementation(libs.ktor.client.core)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
        val cioMain by getting {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        val mingwMain by getting {
            dependencies {
                implementation(libs.ktor.client.winhttp)
            }
        }
    }
}
