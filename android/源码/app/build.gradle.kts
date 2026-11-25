plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.skyhuiyu.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.skyhuiyu.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 4
        versionName = "2.0.0"
    }

    buildTypes {
        release {
            // 与 iOS 的 IPA 保持一致：默认出未签名包，需要自签才能装
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ""
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // 扫码：ZXing 嵌入式，不需要 Google Play 服务
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
