package com.degenhf.auth

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.beans.factory.annotation.Autowired

/**
 * Spring Boot security configuration
 */
@Configuration
@EnableWebSecurity
@EnableScheduling
class SecurityConfig(
    @Autowired private val authHandler: EccAuthHandler
) : WebMvcConfigurer {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .cors { it.configurationSource(corsConfigurationSource()) }
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { authz ->
                authz
                    .requestMatchers("/api/auth/register", "/api/auth/authenticate", "/api/auth/health").permitAll()
                    .requestMatchers("/api/auth/verify", "/api/auth/profile").authenticated()
                    .anyRequest().authenticated()
            }
            .httpBasic { }

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOriginPatterns = listOf("*")
        configuration.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
        configuration.allowedHeaders = listOf("*")
        configuration.allowCredentials = true
        configuration.maxAge = 3600L

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

    /**
     * Scheduled task to clean up expired sessions
     */
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    fun cleanupExpiredSessions() {
        authHandler.cleanupExpiredSessions()
    }
}

/**
 * Application configuration
 */
@Configuration
class AppConfig {

    @Bean
    fun eccAuthOptions(): EccAuthOptions {
        return EccAuthOptions(
            hashIterations = 100000,
            tokenExpiry = java.time.Duration.ofHours(24),
            cacheTtl = java.time.Duration.ofMinutes(5)
        )
    }
}