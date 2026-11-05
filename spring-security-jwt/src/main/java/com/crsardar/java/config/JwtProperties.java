package com.crsardar.java.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds {@code app.jwt.*} from application.properties.
 *
 * @param secret Base64-encoded HMAC-SHA256 key (>= 32 bytes once decoded)
 * @param issuer value written to / required in the {@code iss} claim
 * @param ttl    access-token lifetime
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String secret, String issuer, Duration ttl) {
}
