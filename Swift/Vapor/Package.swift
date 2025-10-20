// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DegenHF-Vapor",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        // Vapor framework
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),

        // JWT authentication
        .package(url: "https://github.com/vapor/jwt.git", from: "4.0.0"),

        // Fluent ORM (for future database integration)
        .package(url: "https://github.com/vapor/fluent.git", from: "4.0.0"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.0.0"),

        // Cryptography
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),

        // Argon2 password hashing
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", branch: "master"),

        // Additional dependencies
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "Run",
            dependencies: [
                .target(name: "App"),
                "Vapor"
            ]
        ),
        .target(
            name: "App",
            dependencies: [
                "Vapor",
                "JWT",
                "Fluent",
                "FluentSQLiteDriver",
                "CryptoSwift",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [
                .unsafeFlags(["-I", "Sources/CArgon2/include"]),
            ]
        ),
        .testTarget(
            name: "AppTests",
            dependencies: [
                .target(name: "App"),
                "XCTVapor"
            ]
        )
    ]
)