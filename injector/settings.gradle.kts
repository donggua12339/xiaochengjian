pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        // smali 项目的 Maven 仓库(dexlib2)
        maven { url = uri("https://raw.github.com/JesusFreke/smali/maven-repository") }
    }
}

rootProject.name = "xcj-injector"
