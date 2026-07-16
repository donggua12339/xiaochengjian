plugins {
    id("org.jetbrains.kotlin.jvm") version "2.0.21"
    application
}

application {
    mainClass.set("com.xcj.injector.InjectorMainKt")
}

dependencies {
    // v2 重构:移除 dexlib2(不再做 dex 字节码注入)
    implementation("net.lingala.zip4j:zip4j:2.11.5")
    implementation("com.github.ajalt.clikt:clikt:4.2.2")
    implementation("org.slf4j:slf4j-simple:2.0.13")
    testImplementation("junit:junit:4.13.2")
}

kotlin {
    jvmToolchain(21)
}

// fat jar(包含所有依赖)
tasks.jar {
    archiveBaseName.set("xcj-injector")
    archiveClassifier.set("all")
    manifest {
        attributes("Main-Class" to "com.xcj.injector.InjectorMainKt")
    }
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
