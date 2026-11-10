package com.gym.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT settings. The secret is supplied through the JWT_SECRET environment variable and must be
 * identical in both services, because the Management Service validates tokens issued here.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String issuer, String secret, long expirationMs) {
}
