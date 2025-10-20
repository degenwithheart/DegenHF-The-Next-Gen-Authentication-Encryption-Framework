plugins {
    kotlin("jvm") version "1.9.10"
    application
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.degenhf"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Ktor server
    implementation("io.ktor:ktor-server-core-jvm:2.3.4")
    implementation("io.ktor:ktor-server-netty-jvm:2.3.4")
    implementation("io.ktor:ktor-server-auth-jvm:2.3.4")
    implementation("io.ktor:ktor-server-auth-jwt-jvm:2.3.4")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:2.3.4")
    implementation("io.ktor:ktor-serialization-jackson-jvm:2.3.4")

    // Cryptography
    implementation("org.bouncycastle:bcprov-jdk18on:1.76")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.76")

    // Password hashing
    implementation("de.mkammerer:argon2-jvm:2.11")
    implementation("com.github.BLAKE3-team:BLAKE3:1.4.0")

    // JWT
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    implementation("io.jsonwebtoken:jjwt-impl:0.11.5")
    implementation("io.jsonwebtoken:jjwt-jackson:0.11.5")

    // Caching
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.6")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.4.11")
    implementation("org.slf4j:slf4j-api:2.0.9")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.15.2")

    // Utilities
    implementation("org.apache.commons:commons-lang3:3.13.0")
    implementation("commons-codec:commons-codec:1.16.0")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-server-test-host-jvm:2.3.4")
    testImplementation("org.testcontainers:junit-jupiter:1.19.0")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.degenhf.auth.ApplicationKt")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.degenhf.auth.ApplicationKt"
    }
}

tasks.shadowJar {
    archiveBaseName.set("degenhf-ktor")
    archiveClassifier.set("")
    archiveVersion.set("")
}