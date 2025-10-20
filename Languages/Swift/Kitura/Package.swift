// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DegenHF-Kitura",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/Kitura/Kitura.git", from: "3.0.0"),
        .package(url: "https://github.com/Kitura/Kitura-CORS.git", from: "3.0.0"),
        .package(url: "https://github.com/Kitura/Swift-JWT.git", from: "4.0.0"),
        .package(url: "https://github.com/Kitura/Kitura-Session.git", from: "4.0.0"),
        .package(url: "https://github.com/IBM-Swift/SwiftyJSON.git", from: "17.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/stregas/BigInt.git", from: "5.3.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "DegenHF-Kitura",
            dependencies: [
                "Kitura",
                "KituraCORS",
                "SwiftJWT",
                "KituraSession",
                "SwiftyJSON",
                .product(name: "Crypto", package: "swift-crypto"),
                "BigInt",
                "CryptoSwift",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "DegenHF-KituraTests",
            dependencies: ["DegenHF-Kitura"]
        ),
    ]
)