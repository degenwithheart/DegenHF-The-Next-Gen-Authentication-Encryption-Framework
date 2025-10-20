package com.degenhf.eccauth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * ECC Authentication Service for Spring Boot
 */
@Service
public class EccAuthService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair keyPair;
    private final Argon2 argon2;
    private final Cache<String, TokenPayload> tokenCache;
    private final Map<String, UserData> users = new ConcurrentHashMap<>();
    private final Map<String, SessionData> sessions = new ConcurrentHashMap<>();

    @Value("${degenhf.ecc.auth.hashIterations:100000}")
    private int hashIterations;

    @Value("${degenhf.ecc.auth.tokenExpiry:3600}")
    private long tokenExpirySeconds;

    @Value("${degenhf.ecc.auth.cacheSize:10000}")
    private long cacheSize;

    @Value("${degenhf.ecc.auth.cacheTtl:300}")
    private long cacheTtlSeconds;

    public EccAuthService() throws Exception {
        // Initialize ECC key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec);
        this.keyPair = keyGen.generateKeyPair();

        // Initialize Argon2
        this.argon2 = Argon2Factory.create();

        // Initialize cache
        this.tokenCache = Caffeine.newBuilder()
                .maximumSize(cacheSize)
                .expireAfterWrite(cacheTtlSeconds, TimeUnit.SECONDS)
                .build();
    }

    public String register(String username, String password) throws Exception {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }

        if (users.containsKey(username)) {
            throw new IllegalArgumentException("User already exists");
        }

        String userId = UUID.randomUUID().toString();
        byte[] salt = generateSalt();
        String passwordHash = hashPassword(password, salt);

        UserData userData = new UserData(userId, username, passwordHash, Instant.now().toEpochMilli());
        users.put(username, userData);

        return userId;
    }

    public String authenticate(String username, String password) throws Exception {
        UserData userData = users.get(username);
        if (userData == null) {
            throw new SecurityException("User not found");
        }

        if (!verifyPassword(password, userData.getPasswordHash())) {
            throw new SecurityException("Invalid password");
        }

        String token = createToken(userData.getId(), username);

        // Cache token
        TokenPayload payload = new TokenPayload(userData.getId(), username,
                Instant.now().plusSeconds(tokenExpirySeconds));
        tokenCache.put(token, payload);

        return token;
    }

    public UserData verifyToken(String token) throws Exception {
        // Check cache first
        TokenPayload cached = tokenCache.getIfPresent(token);
        if (cached != null && cached.getExpiresAt().isAfter(Instant.now())) {
            String username = cached.getUsername();
            UserData user = users.get(username);
            if (user != null) {
                return user;
            }
        }

        // Verify JWT
        try {
            var claims = Jwts.parserBuilder()
                    .setSigningKey(keyPair.getPublic())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String userId = claims.getSubject();
            String username = claims.get("username", String.class);

            UserData user = users.get(username);
            if (user == null || !user.getId().equals(userId)) {
                throw new SecurityException("Invalid token");
            }

            // Cache the result
            TokenPayload payload = new TokenPayload(userId, username,
                    Instant.now().plusSeconds(cacheTtlSeconds));
            tokenCache.put(token, payload);

            return user;
        } catch (Exception e) {
            throw new SecurityException("Invalid or expired token");
        }
    }

    public SessionData createSession(String userId) throws Exception {
        String sessionId = UUID.randomUUID().toString();
        byte[] sessionKey = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(sessionKey);

        SessionData session = new SessionData(
                sessionId,
                userId,
                Base64.getEncoder().encodeToString(sessionKey),
                Instant.now().toEpochMilli(),
                Instant.now().plusSeconds(3600).toEpochMilli() // 1 hour
        );

        sessions.put(sessionId, session);
        return session;
    }

    public SessionData getSession(String sessionId) {
        SessionData session = sessions.get(sessionId);
        if (session != null && session.getExpiresAt() > Instant.now().toEpochMilli()) {
            return session;
        }

        // Clean up expired session
        if (session != null) {
            sessions.remove(sessionId);
        }

        return null;
    }

    private byte[] generateSalt() throws Exception {
        byte[] salt = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        return salt;
    }

    private String hashPassword(String password, byte[] salt) throws Exception {
        // Argon2 hashing
        String argon2Hash = argon2.hash(2, 65536, 4, password.toCharArray(), salt);

        // Additional BLAKE3-like hashing using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(argon2Hash.getBytes());
        sha256.update(salt);
        byte[] combinedHash = sha256.digest();

        // Combine salt + Argon2 + SHA-256
        byte[] result = new byte[salt.length + argon2Hash.getBytes().length + combinedHash.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(argon2Hash.getBytes(), 0, result, salt.length, argon2Hash.getBytes().length);
        System.arraycopy(combinedHash, 0, result, salt.length + argon2Hash.getBytes().length, combinedHash.length);

        return Base64.getEncoder().encodeToString(result);
    }

    private boolean verifyPassword(String password, String storedHash) throws Exception {
        byte[] hashBytes = Base64.getDecoder().decode(storedHash);
        if (hashBytes.length < 64) return false;

        byte[] salt = new byte[32];
        System.arraycopy(hashBytes, 0, salt, 0, 32);

        String computedHash = hashPassword(password, salt);
        return MessageDigest.isEqual(hashBytes, Base64.getDecoder().decode(computedHash));
    }

    private String createToken(String userId, String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userId)
                .claim("username", username)
                .setIssuedAt(java.util.Date.from(now))
                .setExpiration(java.util.Date.from(now.plusSeconds(tokenExpirySeconds)))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.ES256)
                .compact();
    }

    // Data classes
    public static class UserData {
        private final String id;
        private final String username;
        private final String passwordHash;
        private final long createdAt;

        public UserData(String id, String username, String passwordHash, long createdAt) {
            this.id = id;
            this.username = username;
            this.passwordHash = passwordHash;
            this.createdAt = createdAt;
        }

        public String getId() { return id; }
        public String getUsername() { return username; }
        public String getPasswordHash() { return passwordHash; }
        public long getCreatedAt() { return createdAt; }
    }

    public static class SessionData {
        private final String sessionId;
        private final String userId;
        private final String sessionKey;
        private final long createdAt;
        private final long expiresAt;

        public SessionData(String sessionId, String userId, String sessionKey, long createdAt, long expiresAt) {
            this.sessionId = sessionId;
            this.userId = userId;
            this.sessionKey = sessionKey;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }

        public String getSessionId() { return sessionId; }
        public String getUserId() { return userId; }
        public String getSessionKey() { return sessionKey; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    private static class TokenPayload {
        private final String userId;
        private final String username;
        private final Instant expiresAt;

        public TokenPayload(String userId, String username, Instant expiresAt) {
            this.userId = userId;
            this.username = username;
            this.expiresAt = expiresAt;
        }

        public String getUserId() { return userId; }
        public String getUsername() { return username; }
        public Instant getExpiresAt() { return expiresAt; }
    }
}