plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rarn.suicakey"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.rarn.suicakey"
        minSdk = 30
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"
    }
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java", "../../core/src", "../../core-bc/src")
        }
    }
    // 署名鍵：GitHubのSecretsがあればそれ（更新しても同じ鍵）、なければCIが一時的に生成
    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("SK_KS_PATH") ?: "release.jks")
            storePassword = System.getenv("SK_KS_PASS")
            keyAlias = System.getenv("SK_KEY_ALIAS") ?: "sk"
            keyPassword = System.getenv("SK_KS_PASS")
        }
    }
    buildTypes {
        getByName("release") {
            isDebuggable = false          // デバッガ接続を禁止
            isJniDebuggable = false
            isMinifyEnabled = false       // 難読化は次段階（BouncyCastleの設定が必要）
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources {
            excludes += setOf("META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
        }
    }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
