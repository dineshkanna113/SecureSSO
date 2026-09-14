package com.accesshub.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Component
@Slf4j
public class JwtTokenProvider {

    private final SecretKey key;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;
    private final String issuer;

    public JwtTokenProvider(
            @Value("${accesshub.jwt.secret}") String secret,
            @Value("${accesshub.jwt.access-token-expiration-ms:900000}") long accessTokenExpirationMs,
            @Value("${accesshub.jwt.refresh-token-expiration-ms:604800000}") long refreshTokenExpirationMs,
            @Value("${accesshub.jwt.issuer:AccessHub-IAM}") String issuer) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
        this.issuer = issuer;
    }

    public String generateAccessToken(UUID userId, UUID tenantId, String email, Set<String> roles, Set<String> authorities) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(accessTokenExpirationMs);

        return Jwts.builder()
                .subject(userId.toString())
                .issuer(issuer)
                .claim("tenantId", tenantId.toString())
                .claim("email", email)
                .claim("roles", roles)
                .claim("authorities", authorities)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(UUID userId, UUID tenantId, String tokenId) {
        return generateRefreshToken(userId, tenantId, tokenId, tokenId, null, 1);
    }

    public String generateRefreshToken(UUID userId, UUID tenantId, String tokenId, String tokenFamily, UUID sessionId, int sequenceNumber) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(refreshTokenExpirationMs);

        var builder = Jwts.builder()
                .id(tokenId)
                .subject(userId.toString())
                .issuer(issuer)
                .claim("tenantId", tenantId.toString())
                .claim("type", "REFRESH")
                .claim("tokenFamily", tokenFamily)
                .claim("sequenceNumber", sequenceNumber)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key);

        if (sessionId != null) {
            builder.claim("sessionId", sessionId.toString());
        }

        return builder.compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(getClaims(token).getSubject());
    }

    public UUID getTenantIdFromToken(String token) {
        String tenantIdStr = getClaims(token).get("tenantId", String.class);
        return tenantIdStr != null ? UUID.fromString(tenantIdStr) : null;
    }

    public String getTokenIdFromRefreshToken(String token) {
        return getClaims(token).getId();
    }

    public String getTokenFamilyFromRefreshToken(String token) {
        String family = getClaims(token).get("tokenFamily", String.class);
        return family != null ? family : getTokenIdFromRefreshToken(token);
    }

    public UUID getSessionIdFromRefreshToken(String token) {
        String sessionIdStr = getClaims(token).get("sessionId", String.class);
        return sessionIdStr != null ? UUID.fromString(sessionIdStr) : null;
    }

    public int getSequenceNumberFromRefreshToken(String token) {
        Integer seq = getClaims(token).get("sequenceNumber", Integer.class);
        return seq != null ? seq : 1;
    }

    public long getRemainingExpirationMs(String token) {
        Date expiration = getClaims(token).getExpiration();
        long remaining = expiration.getTime() - System.currentTimeMillis();
        return Math.max(remaining, 0);
    }
}
