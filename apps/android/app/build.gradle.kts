plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The engine (libvpngate_uniffi.so for three ABIs and its Kotlin bindings) comes from scripts/build-android-engine.sh.
val engineDir = rootProject.file("../../build/android-engine")
val bundledList = rootProject.file("../../assets/VPNGate.dat")
val generatedAssets = layout.buildDirectory.dir("generated/bundle")

val copyBundledList by tasks.registering(Copy::class) {
    from(bundledList)
    into(generatedAssets)
}

android {
    namespace = "com.yazdanifar.vpngate.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.yazdanifar.vpngate"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = rootProject.file("../../VERSION").readText().trim()
    }

    buildFeatures { compose = true }

    // Release key from the environment (CI secrets); without it the release build is signed with the debug key so it
    // still installs, and is not fit for distribution.
    val releaseStore = System.getenv("VPNGATE_KEYSTORE")?.let { rootProject.file(it) }
    signingConfigs {
        if (releaseStore != null) {
            create("release") {
                storeFile = releaseStore
                storePassword = System.getenv("VPNGATE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("VPNGATE_KEY_ALIAS")
                keyPassword = System.getenv("VPNGATE_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            // No minification: the UniFFI bindings reach the engine through JNA reflection.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    sourceSets["main"].apply {
        // KGP compiles Kotlin files found in the java source dirs too.
        java.srcDir(engineDir.resolve("kotlin"))
        jniLibs.srcDir(engineDir.resolve("jniLibs"))
        assets.srcDir(files(generatedAssets).builtBy(copyBundledList))
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig.testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

    testOptions { unitTests.isReturnDefaultValues = true }
}

kotlin { jvmToolchain(17) }

tasks.matching { it.name.matches(Regex("(merge.*Assets|(?i).*lint.*)")) }.configureEach { dependsOn(copyBundledList) }

dependencies {
    implementation(project(":core"))
    // uniffi's Kotlin bindings call the engine through JNA; the aar carries the Android build of libjnidispatch.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation(platform("androidx.compose:compose-bom:2024.11.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation(kotlin("test"))
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.11.00"))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
