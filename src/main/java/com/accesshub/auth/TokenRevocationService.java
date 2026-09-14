package com.accesshub.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenRevocationService {

    private final RedisTemplate<String, String> redisTemplate;
    private final Map<String, Long> fallbackRevokedMap = new ConcurrentHashMap<>();

    private static final String REVOKED_TOKEN_PREFIX = "revoked:token:";
    private static final String REVOKED_FAMILY_PREFIX = "revoked:family:";

    public void revokeRefreshToken(String tokenId, long expirationMs) {
        if (tokenId == null || tokenId.isBlank()) return;
        revokeKey(REVOKED_TOKEN_PREFIX + tokenId, expirationMs);
    }

    public void revokeTokenFamily(String familyId, long expirationMs) {
        if (familyId == null || familyId.isBlank()) return;
        revokeKey(REVOKED_FAMILY_PREFIX + familyId, expirationMs);
    }

    public boolean isRevoked(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) return true;
        return isKeyRevoked(REVOKED_TOKEN_PREFIX + tokenId);
    }

    public boolean isFamilyRevoked(String familyId) {
        if (familyId == null || familyId.isBlank()) return false;
        return isKeyRevoked(REVOKED_FAMILY_PREFIX + familyId);
    }

    private void revokeKey(String key, long expirationMs) {
        try {
            if (expirationMs > 0) {
                redisTemplate.opsForValue().set(key, "revoked", expirationMs, TimeUnit.MILLISECONDS);
            } else {
                redisTemplate.opsForValue().set(key, "revoked");
            }
        } catch (Exception e) {
            log.warn("Redis unavailable, using memory fallback for key: {}", key);
            fallbackRevokedMap.put(key, System.currentTimeMillis() + Math.max(expirationMs, 604800000L));
        }
    }

    private boolean isKeyRevoked(String key) {
        try {
            Boolean hasKey = redisTemplate.hasKey(key);
            if (Boolean.TRUE.equals(hasKey)) {
                return true;
            }
        } catch (Exception e) {
            Long expiry = fallbackRevokedMap.get(key);
            if (expiry != null) {
                if (System.currentTimeMillis() < expiry) {
                    return true;
                } else {
                    fallbackRevokedMap.remove(key);
                }
            }
        }
        return false;
    }
}
