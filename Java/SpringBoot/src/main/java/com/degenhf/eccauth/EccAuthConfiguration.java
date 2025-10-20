package com.degenhf.eccauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * ECC Authentication Configuration for Spring Boot
 */
@Configuration
@ConfigurationProperties(prefix = "degenhf.ecc.auth")
public class EccAuthConfiguration {

    private int hashIterations = 100000;
    private long tokenExpiry = 3600;
    private long cacheSize = 10000;
    private long cacheTtl = 300;

    @Bean
    public EccAuthService eccAuthService() throws Exception {
        return new EccAuthService();
    }

    // Getters and setters
    public int getHashIterations() { return hashIterations; }
    public void setHashIterations(int hashIterations) { this.hashIterations = hashIterations; }

    public long getTokenExpiry() { return tokenExpiry; }
    public void setTokenExpiry(long tokenExpiry) { this.tokenExpiry = tokenExpiry; }

    public long getCacheSize() { return cacheSize; }
    public void setCacheSize(long cacheSize) { this.cacheSize = cacheSize; }

    public long getCacheTtl() { return cacheTtl; }
    public void setCacheTtl(long cacheTtl) { this.cacheTtl = cacheTtl; }
}