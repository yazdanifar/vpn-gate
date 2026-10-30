plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.jvm") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
    // Screenshot goldens of the Compose screens (JVM, no emulator). 1.3.5 is the last release that runs on JDK 17 and AGP 8.7;
    // 2.0.0-alpha needs Java 21 and a newer Gradle/Kotlin (DECISIONS U35).
    id("app.cash.paparazzi") version "1.3.5" apply false
}
