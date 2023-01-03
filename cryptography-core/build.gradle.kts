plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()
    js {
        browser()
        nodejs()
    }
    linuxX64()
    macosX64()
    macosArm64()
    mingwX64()

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyIo)
            }
        }
    }
}
