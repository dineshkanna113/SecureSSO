package com.accesshub.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginRateLimiterService {

    private final RedisTemplate<String, String> redisTemplate;

    @Value("${accesshub.rate-limit.max-login-attempts:5}")
    private int maxAttempts;

    @Value("${accesshub.rate-limit.lockout-duration-minutes:15}")
    private int lockoutMinutes;

    private static final String IP_ATTEMPTS_PREFIX = "rl:ip:";
    private static final String ACCOUNT_ATTEMPTS_PREFIX = "rl:account:";
    private static final int MAX_IP_RPM = 60; // Max 60 requests/minute per IP

    private final Map<String, Integer> fallbackMap = new ConcurrentHashMap<>();
    private final Map<String, Long> fallbackExpiryMap = new ConcurrentHashMap<>();

    public boolean isIpRateLimited(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) return false;
        String key = IP_ATTEMPTS_PREFIX + ipAddress.trim();
        return getCount(key) >= MAX_IP_RPM;
    }

    public boolean isAccountLocked(UUID tenantId, String email) {
        if (email == null || email.isBlank()) return false;
        String tenantStr = tenantId != null ? tenantId.toString() : "global";
        String key = ACCOUNT_ATTEMPTS_PREFIX + tenantStr + ":" + email.toLowerCase().trim();
        return getCount(key) >= maxAttempts;
    }

    public boolean isBlocked(String ipAddress, String username) {
        return isIpRateLimited(ipAddress) || isAccountLocked(null, username);
    }

    public void recordFailedAttempt(UUID tenantId, String ipAddress, String email) {
        if (ipAddress != null && !ipAddress.isBlank()) {
            String ipKey = IP_ATTEMPTS_PREFIX + ipAddress.trim();
            incrementKey(ipKey, 60, TimeUnit.SECONDS);
        }

        if (email != null && !email.isBlank()) {
            String tenantStr = tenantId != null ? tenantId.toString() : "global";
            String accountKey = ACCOUNT_ATTEMPTS_PREFIX + tenantStr + ":" + email.toLowerCase().trim();
            incrementKey(accountKey, lockoutMinutes * 60L, TimeUnit.SECONDS);
            log.info("Recorded failed attempt for account {} in tenant {} from IP {}", email, tenantStr, ipAddress);
        }
    }

    public void recordFailedAttempt(String ipAddress, String username) {
        recordFailedAttempt(null, ipAddress, username);
    }

    public void resetAttempts(UUID tenantId, String email) {
        if (email == null || email.isBlank()) return;
        String tenantStr = tenantId != null ? tenantId.toString() : "global";
        String accountKey = ACCOUNT_ATTEMPTS_PREFIX + tenantStr + ":" + email.toLowerCase().trim();
        deleteKey(accountKey);
    }

    public void resetAttempts(String ipAddress, String username) {
        resetAttempts((UUID) null, username);
    }

    private int getCount(String key) {
        try {
            String val = redisTemplate.opsForValue().get(key);
            return val != null ? Integer.parseInt(val) : 0;
        } catch (Exception e) {
            cleanExpiredFallback(key);
            return fallbackMap.getOrDefault(key, 0);
        }
    }

    private void incrementKey(String key, long ttlSeconds, TimeUnit timeUnit) {
        try {
            Long count = redisTemplate.opsForValue().increment(key);
            if (count != null && count == 1) {
                redisTemplate.expire(key, ttlSeconds, timeUnit);
            }
        } catch (Exception e) {
            cleanExpiredFallback(key);
            fallbackMap.merge(key, 1, Integer::sum);
            fallbackExpiryMap.putIfAbsent(key, System.currentTimeMillis() + (ttlSeconds * 1000));
        }
    }

    private void deleteKey(String key) {
        try {
            redisTemplate.delete(key);
        } catch (Exception e) {
            fallbackMap.remove(key);
            fallbackExpiryMap.remove(key);
        }
    }

    private void cleanExpiredFallback(String key) {
        Long exp = fallbackExpiryMap.get(key);
        if (exp != null && System.currentTimeMillis() > exp) {
            fallbackMap.remove(key);
            fallbackExpiryMap.remove(key);
        }
    }
}
