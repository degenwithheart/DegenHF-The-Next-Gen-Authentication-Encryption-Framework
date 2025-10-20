plugins {
    kotlin("jvm") version "1.9.10"
    kotlin("plugin.spring") version "1.9.10"
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.degenhf"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring Boot
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("org.springframework.boot:spring-boot-configuration-processor")

    // JWT
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    implementation("io.jsonwebtoken:jjwt-impl:0.11.5")
    implementation("io.jsonwebtoken:jjwt-jackson:0.11.5")

    // Cryptography
    implementation("org.bouncycastle:bcprov-jdk18on:1.76")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.76")

    // Password hashing
    implementation("de.mkammerer:argon2-jvm:2.11")
    implementation("com.github.BLAKE3-team:BLAKE3:1.4.0")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.15.2")

    // Utilities
    implementation("org.apache.commons:commons-lang3:3.13.0")
    implementation("commons-codec:commons-codec:1.16.0")

    // Kotlin
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Test dependencies
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.h2database:h2")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

tasks.shadowJar {
    archiveBaseName.set("degenhf-spring-boot")
    archiveClassifier.set("")
    archiveVersion.set("")
}