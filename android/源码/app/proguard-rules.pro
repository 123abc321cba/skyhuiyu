# 默认不混淆；保留 okhttp/okio 的反射入口以防后续开启 minify
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
