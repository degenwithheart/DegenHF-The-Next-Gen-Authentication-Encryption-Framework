<?php

namespace DegenHF\EccAuth;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Facades\Log;

/**
 * ECC Authentication Service for Laravel
 */
class EccAuthService
{
    private array $keyPair;
    private Cache $cache;
    private array $users = [];
    private array $sessions = [];

    private int $hashIterations;
    private int $tokenExpiry;
    private int $cacheSize;
    private int $cacheTtl;

    public function __construct(Cache $cache, array $config = [])
    {
        $this->cache = $cache;
        $this->hashIterations = $config['hash_iterations'] ?? 100000;
        $this->tokenExpiry = $config['token_expiry'] ?? 3600;
        $this->cacheSize = $config['cache_size'] ?? 10000;
        $this->cacheTtl = $config['cache_ttl'] ?? 300;

        $this->initializeKeyPair();
    }

    private function initializeKeyPair(): void
    {
        $this->keyPair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp256k1'
        ]);

        if (!$this->keyPair) {
            throw new \RuntimeException('Failed to generate ECC key pair');
        }
    }

    public function register(string $username, string $password): string
    {
        if (empty($username) || empty($password)) {
            throw new \InvalidArgumentException('Username and password are required');
        }

        if (strlen($password) < 8) {
            throw new \InvalidArgumentException('Password must be at least 8 characters long');
        }

        if (isset($this->users[$username])) {
            throw new \InvalidArgumentException('User already exists');
        }

        $userId = $this->generateUserId();
        $salt = $this->generateSalt();
        $passwordHash = $this->hashPassword($password, $salt);

        $this->users[$username] = [
            'id' => $userId,
            'username' => $username,
            'password_hash' => $passwordHash,
            'created_at' => time(),
        ];

        return $userId;
    }

    public function authenticate(string $username, string $password): string
    {
        $user = $this->users[$username] ?? null;
        if (!$user) {
            throw new \RuntimeException('User not found');
        }

        if (!$this->verifyPassword($password, $user['password_hash'])) {
            throw new \RuntimeException('Invalid password');
        }

        $token = $this->createToken($user['id'], $username);

        // Cache token
        $this->cache->put(
            "ecc_auth_token:{$user['id']}",
            ['token' => $token, 'expires' => time() + $this->cacheTtl],
            $this->cacheTtl
        );

        return $token;
    }

    public function verifyToken(string $token): array
    {
        // Check cache first
        $cached = $this->cache->get("ecc_auth_token_payload:" . hash('sha256', $token));
        if ($cached && $cached['expires'] > time()) {
            return $cached['user'];
        }

        // Verify JWT
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid token format');
        }

        $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[0])), true);
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1])), true);
        $signature = str_replace(['-', '_'], ['+', '/'], $parts[2]);

        if (!$payload || !isset($payload['sub']) || !isset($payload['username'])) {
            throw new \RuntimeException('Invalid token payload');
        }

        // Verify signature
        $data = $parts[0] . '.' . $parts[1];
        $verified = openssl_verify($data, base64_decode($signature), $this->keyPair, OPENSSL_ALGO_SHA256);

        if ($verified !== 1) {
            throw new \RuntimeException('Invalid token signature');
        }

        // Check expiry
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new \RuntimeException('Token expired');
        }

        // Find user
        $user = null;
        foreach ($this->users as $u) {
            if ($u['id'] === $payload['sub']) {
                $user = $u;
                break;
            }
        }

        if (!$user) {
            throw new \RuntimeException('User not found');
        }

        // Cache the result
        $this->cache->put(
            "ecc_auth_token_payload:" . hash('sha256', $token),
            ['user' => $user, 'expires' => time() + $this->cacheTtl],
            $this->cacheTtl
        );

        return $user;
    }

    public function createSession(string $userId): array
    {
        $sessionId = $this->generateSessionId();
        $sessionKey = bin2hex(random_bytes(32));

        $session = [
            'session_id' => $sessionId,
            'user_id' => $userId,
            'session_key' => $sessionKey,
            'created_at' => time(),
            'expires_at' => time() + 3600, // 1 hour
        ];

        $this->sessions[$sessionId] = $session;
        return $session;
    }

    public function getSession(string $sessionId): ?array
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session && $session['expires_at'] > time()) {
            return $session;
        }

        // Clean up expired session
        if ($session) {
            unset($this->sessions[$sessionId]);
        }

        return null;
    }

    private function generateUserId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function generateSessionId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function generateSalt(): string
    {
        return random_bytes(32);
    }

    private function hashPassword(string $password, string $salt): string
    {
        // Argon2 hashing
        $argon2Hash = sodium_crypto_pwhash(
            32,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
        );

        // Additional BLAKE3-like hashing using SHA-256
        $combined = $salt . $argon2Hash;
        $blake3Hash = hash('sha256', $combined);

        // Combine salt + Argon2 + SHA-256
        return base64_encode($salt . $argon2Hash . hex2bin($blake3Hash));
    }

    private function verifyPassword(string $password, string $storedHash): bool
    {
        $hashBytes = base64_decode($storedHash);
        if (strlen($hashBytes) < 96) { // 32 + 32 + 32
            return false;
        }

        $salt = substr($hashBytes, 0, 32);
        $computedHash = $this->hashPassword($password, $salt);

        return hash_equals($hashBytes, base64_decode($computedHash));
    }

    private function createToken(string $userId, string $username): string
    {
        $header = json_encode(['alg' => 'ES256', 'typ' => 'JWT']);
        $payload = json_encode([
            'sub' => $userId,
            'username' => $username,
            'iat' => time(),
            'exp' => time() + $this->tokenExpiry,
        ]);

        $headerEncoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $payloadEncoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        $data = $headerEncoded . '.' . $payloadEncoded;

        openssl_sign($data, $signature, $this->keyPair, OPENSSL_ALGO_SHA256);
        $signatureEncoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return $data . '.' . $signatureEncoded;
    }
}