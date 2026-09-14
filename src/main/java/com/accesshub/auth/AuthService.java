package com.accesshub.auth;

import com.accesshub.audit.AuditLogService;
import com.accesshub.auth.dto.*;
import com.accesshub.exception.InvalidCredentialsException;
import com.accesshub.exception.RateLimitExceededException;
import com.accesshub.exception.ResourceNotFoundException;
import com.accesshub.exception.TokenRevokedException;
import com.accesshub.permission.Permission;
import com.accesshub.permission.PermissionRepository;
import com.accesshub.role.Role;
import com.accesshub.role.RoleRepository;
import com.accesshub.security.JwtTokenProvider;
import com.accesshub.security.TokenHashUtil;
import com.accesshub.tenant.Tenant;
import com.accesshub.tenant.TenantContext;
import com.accesshub.tenant.TenantRepository;
import com.accesshub.user.User;
import com.accesshub.user.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRevocationService tokenRevocationService;
    private final LoginRateLimiterService loginRateLimiterService;
    private final AuditLogService auditLogService;

    private static final String DUMMY_BCRYPT_HASH = "$2a$12$e8Y6bFzX/3UoJ4U.V8qK4OM1LzK7oQyB.0A8n2wF9X8B7m6oP4C3W";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public RegisterTenantResponse registerTenant(RegisterTenantRequest request, String ipAddress, String userAgent) {
        if (tenantRepository.existsBySlug(request.getTenantSlug())) {
            throw new IllegalArgumentException("Tenant slug '" + request.getTenantSlug() + "' is already taken");
        }

        // 1. Ensure Baseline Permissions Exist in Catalog
        ensureBaselinePermissions();

        // 2. Create Tenant
        Tenant tenant = Tenant.builder()
                .name(request.getTenantName())
                .slug(request.getTenantSlug().toLowerCase().trim())
                .status(Tenant.TenantStatus.ACTIVE)
                .build();
        tenant = tenantRepository.save(tenant);

        // 3. Fetch system permissions
        List<Permission> allPermissions = permissionRepository.findAll();
        Set<Permission> adminPerms = new HashSet<>(allPermissions);

        // 4. Create Tenant Admin Role
        Role adminRole = Role.builder()
                .tenantId(tenant.getId())
                .name("TENANT_ADMIN")
                .description("Full administrative control over tenant resources")
                .isSystemRole(true)
                .permissions(adminPerms)
                .build();
        adminRole = roleRepository.save(adminRole);

        // 5. Create Default User Role
        Set<Permission> userPerms = permissionRepository.findByCodeIn(Set.of("USER_READ"));
        Role userRole = Role.builder()
                .tenantId(tenant.getId())
                .name("USER")
                .description("Regular tenant user profile access")
                .isSystemRole(true)
                .permissions(userPerms)
                .build();
        roleRepository.save(userRole);

        // 6. Create Admin User
        User adminUser = User.builder()
                .tenantId(tenant.getId())
                .email(request.getAdminEmail().toLowerCase().trim())
                .passwordHash(passwordEncoder.encode(request.getAdminPassword()))
                .firstName(request.getAdminFirstName())
                .lastName(request.getAdminLastName())
                .enabled(true)
                .locked(false)
                .roles(Set.of(adminRole))
                .build();
        adminUser = userRepository.save(adminUser);

        // 7. Audit log
        auditLogService.recordAuditEvent(
                tenant.getId(),
                adminUser.getId(),
                adminUser.getEmail(),
                "TENANT_REGISTERED",
                "TENANT",
                tenant.getId().toString(),
                ipAddress,
                userAgent,
                "Registered tenant '" + tenant.getName() + "'"
        );

        return RegisterTenantResponse.builder()
                .tenantId(tenant.getId())
                .tenantName(tenant.getName())
                .tenantSlug(tenant.getSlug())
                .adminUserId(adminUser.getId())
                .adminEmail(adminUser.getEmail())
                .message("Tenant registered successfully")
                .build();
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String ipAddress, String userAgent) {
        String slug = request.getTenantSlug() != null ? request.getTenantSlug().toLowerCase().trim() : "";
        String email = request.getEmail() != null ? request.getEmail().toLowerCase().trim() : "";

        // 1. Dual-Bucket Rate Limit Check
        if (loginRateLimiterService.isIpRateLimited(ipAddress)) {
            auditLogService.recordAuditEvent(null, null, email, "LOGIN_BLOCKED_IP_RATE_LIMIT", "USER", email, ipAddress, userAgent, "IP throttled");
            throw new RateLimitExceededException("Too many login requests from your IP. Please try again shortly.");
        }

        // 2. Lookup Tenant & User with constant-time protection
        Optional<Tenant> tenantOpt = tenantRepository.findBySlug(slug);
        if (tenantOpt.isEmpty() || tenantOpt.get().getStatus() != Tenant.TenantStatus.ACTIVE) {
            passwordEncoder.matches(request.getPassword(), DUMMY_BCRYPT_HASH);
            loginRateLimiterService.recordFailedAttempt(null, ipAddress, email);
            throw new InvalidCredentialsException("Invalid tenant, email, or password");
        }

        Tenant tenant = tenantOpt.get();

        if (loginRateLimiterService.isAccountLocked(tenant.getId(), email)) {
            auditLogService.recordAuditEvent(tenant.getId(), null, email, "LOGIN_BLOCKED_ACCOUNT_LOCKOUT", "USER", email, ipAddress, userAgent, "Account locked out");
            throw new RateLimitExceededException("Account temporarily locked due to repeated failed attempts. Please try again in 15 minutes.");
        }

        Optional<User> userOpt = userRepository.findByEmailAndTenantId(email, tenant.getId());
        if (userOpt.isEmpty()) {
            passwordEncoder.matches(request.getPassword(), DUMMY_BCRYPT_HASH);
            loginRateLimiterService.recordFailedAttempt(tenant.getId(), ipAddress, email);
            auditLogService.recordAuditEvent(tenant.getId(), null, email, "LOGIN_FAILED", "USER", email, ipAddress, userAgent, "User not found");
            throw new InvalidCredentialsException("Invalid tenant, email, or password");
        }

        User user = userOpt.get();

        if (!user.isEnabled() || user.isLocked()) {
            passwordEncoder.matches(request.getPassword(), DUMMY_BCRYPT_HASH);
            auditLogService.recordAuditEvent(tenant.getId(), user.getId(), email, "LOGIN_FAILED", "USER", user.getId().toString(), ipAddress, userAgent, "User disabled or locked");
            throw new InvalidCredentialsException("Invalid tenant, email, or password");
        }

        // 3. Verify Password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            loginRateLimiterService.recordFailedAttempt(tenant.getId(), ipAddress, email);
            auditLogService.recordAuditEvent(tenant.getId(), user.getId(), email, "LOGIN_FAILED", "USER", user.getId().toString(), ipAddress, userAgent, "Invalid password");
            throw new InvalidCredentialsException("Invalid tenant, email, or password");
        }

        // Reset rate limit on success
        loginRateLimiterService.resetAttempts(tenant.getId(), email);

        // 4. Create User Session
        String sessionIdentifier = UUID.randomUUID().toString();
        Instant sessionExpiry = Instant.now().plus(7, ChronoUnit.DAYS);

        UserSession session = UserSession.builder()
                .tenantId(tenant.getId())
                .userId(user.getId())
                .sessionIdentifier(sessionIdentifier)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceInfo(parseDeviceInfo(userAgent))
                .active(true)
                .expiresAt(sessionExpiry)
                .build();
        session = userSessionRepository.save(session);

        // 5. Generate Token Family & Tokens
        String tokenFamily = UUID.randomUUID().toString();
        String refreshTokenId = UUID.randomUUID().toString();

        Set<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        Set<String> authorities = new HashSet<>();
        for (Role role : user.getRoles()) {
            authorities.add("ROLE_" + role.getName());
            for (Permission p : role.getPermissions()) {
                authorities.add(p.getCode());
            }
        }

        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), tenant.getId(), user.getEmail(), roleNames, authorities);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId(), tenant.getId(), refreshTokenId, tokenFamily, session.getId(), 1);

        // Persist Hashed Refresh Token in PostgreSQL
        RefreshToken tokenEntity = RefreshToken.builder()
                .sessionId(session.getId())
                .tenantId(tenant.getId())
                .userId(user.getId())
                .tokenHash(TokenHashUtil.hash(refreshToken))
                .tokenFamily(tokenFamily)
                .sequenceNumber(1)
                .revoked(false)
                .expiresAt(sessionExpiry)
                .build();
        refreshTokenRepository.save(tokenEntity);

        auditLogService.recordAuditEvent(tenant.getId(), user.getId(), user.getEmail(), "LOGIN_SUCCESS", "USER", user.getId().toString(), ipAddress, userAgent, "User authenticated successfully");

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresInMs(900000)
                .userId(user.getId())
                .tenantId(tenant.getId())
                .email(user.getEmail())
                .roles(roleNames)
                .permissions(authorities)
                .build();
    }

    @Transactional
    public LoginResponse refreshToken(RefreshTokenRequest request, String ipAddress, String userAgent) {
        String token = request.getRefreshToken();
        if (!jwtTokenProvider.validateToken(token)) {
            throw new InvalidCredentialsException("Invalid or expired refresh token");
        }

        Claims claims = jwtTokenProvider.getClaims(token);
        String tokenType = claims.get("type", String.class);
        if (!"REFRESH".equals(tokenType)) {
            throw new InvalidCredentialsException("Token provided is not a refresh token");
        }

        String tokenId = jwtTokenProvider.getTokenIdFromRefreshToken(token);
        String tokenFamily = jwtTokenProvider.getTokenFamilyFromRefreshToken(token);
        UUID userId = jwtTokenProvider.getUserIdFromToken(token);
        UUID tenantId = jwtTokenProvider.getTenantIdFromToken(token);
        UUID sessionId = jwtTokenProvider.getSessionIdFromRefreshToken(token);
        int sequenceNumber = jwtTokenProvider.getSequenceNumberFromRefreshToken(token);

        long remainingMs = jwtTokenProvider.getRemainingExpirationMs(token);
        String tokenHash = TokenHashUtil.hash(token);

        // 1. Check Redis Fast Revocation
        if (tokenRevocationService.isRevoked(tokenId) || tokenRevocationService.isFamilyRevoked(tokenFamily)) {
            handleReuseDetected(tenantId, userId, tokenFamily, remainingMs, ipAddress, userAgent);
        }

        // 2. Lookup in PostgreSQL
        Optional<RefreshToken> storedTokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

        if (storedTokenOpt.isEmpty() || storedTokenOpt.get().isRevoked()) {
            // REUSE DETECTED: An already-revoked or non-existent token was presented!
            handleReuseDetected(tenantId, userId, tokenFamily, remainingMs, ipAddress, userAgent);
        }

        RefreshToken storedToken = storedTokenOpt.get();

        // 3. Verify User Status
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User or tenant not found for token"));

        if (!user.isEnabled() || user.isLocked()) {
            throw new InvalidCredentialsException("User account is disabled or locked");
        }

        // 4. Revoke Old Refresh Token (Single-Use Token Rotation)
        storedToken.setRevoked(true);
        storedToken.setRevokedReason("ROTATED");
        refreshTokenRepository.save(storedToken);
        tokenRevocationService.revokeRefreshToken(tokenId, remainingMs);

        // 5. Issue New Child Token in Same Family
        String newRefreshTokenId = UUID.randomUUID().toString();
        int nextSeq = sequenceNumber + 1;

        Set<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        Set<String> authorities = new HashSet<>();
        for (Role role : user.getRoles()) {
            authorities.add("ROLE_" + role.getName());
            for (Permission p : role.getPermissions()) {
                authorities.add(p.getCode());
            }
        }

        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId(), tenantId, user.getEmail(), roleNames, authorities);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getId(), tenantId, newRefreshTokenId, tokenFamily, sessionId, nextSeq);

        RefreshToken newStoredToken = RefreshToken.builder()
                .sessionId(sessionId)
                .tenantId(tenantId)
                .userId(user.getId())
                .tokenHash(TokenHashUtil.hash(newRefreshToken))
                .tokenFamily(tokenFamily)
                .sequenceNumber(nextSeq)
                .revoked(false)
                .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                .build();
        refreshTokenRepository.save(newStoredToken);

        auditLogService.recordAuditEvent(tenantId, user.getId(), user.getEmail(), "REFRESH_TOKEN_ROTATED", "USER", user.getId().toString(), ipAddress, userAgent, "Rotated refresh token sequence " + nextSeq);

        return LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresInMs(900000)
                .userId(user.getId())
                .tenantId(tenantId)
                .email(user.getEmail())
                .roles(roleNames)
                .permissions(authorities)
                .build();
    }

    private void handleReuseDetected(UUID tenantId, UUID userId, String tokenFamily, long remainingMs, String ipAddress, String userAgent) {
        log.warn("🚨 REFRESH TOKEN REUSE DETECTED for family {}! Revoking full family.", tokenFamily);
        refreshTokenRepository.revokeTokenFamily(tokenFamily, "REUSE_DETECTED");
        tokenRevocationService.revokeTokenFamily(tokenFamily, Math.max(remainingMs, 604800000L));
        auditLogService.recordAuditEvent(tenantId, userId, null, "REFRESH_TOKEN_REUSE_DETECTED", "TOKEN_FAMILY", tokenFamily, ipAddress, userAgent, "Compromise alert: refresh token reuse detected");
        throw new TokenRevokedException("Refresh token reuse detected. The complete token family and session have been revoked for security.");
    }

    @Transactional
    public void logout(LogoutRequest request, String ipAddress, String userAgent) {
        String token = request.getRefreshToken();
        if (jwtTokenProvider.validateToken(token)) {
            String tokenId = jwtTokenProvider.getTokenIdFromRefreshToken(token);
            long remainingMs = jwtTokenProvider.getRemainingExpirationMs(token);
            UUID userId = jwtTokenProvider.getUserIdFromToken(token);
            UUID tenantId = jwtTokenProvider.getTenantIdFromToken(token);
            UUID sessionId = jwtTokenProvider.getSessionIdFromRefreshToken(token);

            tokenRevocationService.revokeRefreshToken(tokenId, remainingMs);

            String tokenHash = TokenHashUtil.hash(token);
            refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(rt -> {
                rt.setRevoked(true);
                rt.setRevokedReason("LOGOUT");
                refreshTokenRepository.save(rt);
            });

            if (sessionId != null) {
                userSessionRepository.findById(sessionId).ifPresent(s -> {
                    s.setActive(false);
                    userSessionRepository.save(s);
                });
            }

            auditLogService.recordAuditEvent(tenantId, userId, null, "LOGOUT", "USER", userId != null ? userId.toString() : null, ipAddress, userAgent, "User logged out of session");
        }
    }

    @Transactional
    public void logoutAll(String ipAddress, String userAgent) {
        UUID tenantId = TenantContext.getTenantId();
        UUID userId = TenantContext.getUserId();
        if (tenantId == null || userId == null) {
            throw new InvalidCredentialsException("Authenticated user context required for logout-all");
        }

        userSessionRepository.deactivateAllUserSessions(tenantId, userId);
        refreshTokenRepository.revokeAllUserTokens(tenantId, userId, "LOGOUT_ALL_SESSIONS");

        auditLogService.recordAuditEvent(tenantId, userId, null, "LOGOUT_ALL_SESSIONS", "USER", userId.toString(), ipAddress, userAgent, "User terminated all active sessions");
    }

    @Transactional
    public void changePassword(ChangePasswordRequest request, String ipAddress, String userAgent) {
        UUID tenantId = TenantContext.getTenantId();
        UUID userId = TenantContext.getUserId();
        if (tenantId == null || userId == null) {
            throw new InvalidCredentialsException("Authenticated user context required to change password");
        }

        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            auditLogService.recordAuditEvent(tenantId, userId, user.getEmail(), "PASSWORD_CHANGE_FAILED", "USER", userId.toString(), ipAddress, userAgent, "Invalid current password");
            throw new InvalidCredentialsException("Current password does not match");
        }

        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            throw new IllegalArgumentException("New password cannot be identical to current password");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Security requirement: Revoke all existing sessions and refresh tokens on password change!
        userSessionRepository.deactivateAllUserSessions(tenantId, userId);
        refreshTokenRepository.revokeAllUserTokens(tenantId, userId, "PASSWORD_CHANGED");

        auditLogService.recordAuditEvent(tenantId, userId, user.getEmail(), "PASSWORD_CHANGED", "USER", userId.toString(), ipAddress, userAgent, "Password changed successfully; all active sessions revoked");
    }

    @Transactional
    public PasswordResetResponse forgotPassword(ForgotPasswordRequest request, String ipAddress, String userAgent) {
        String slug = request.getTenantSlug().toLowerCase().trim();
        String email = request.getEmail().toLowerCase().trim();

        Optional<Tenant> tenantOpt = tenantRepository.findBySlug(slug);
        if (tenantOpt.isPresent()) {
            Tenant tenant = tenantOpt.get();
            Optional<User> userOpt = userRepository.findByEmailAndTenantId(email, tenant.getId());

            if (userOpt.isPresent()) {
                User user = userOpt.get();
                // Invalidate any existing reset tokens
                List<PasswordResetToken> activeTokens = passwordResetTokenRepository.findByTenantIdAndUserIdAndUsedFalse(tenant.getId(), user.getId());
                activeTokens.forEach(t -> t.setUsed(true));
                passwordResetTokenRepository.saveAll(activeTokens);

                // Generate secure random reset token
                byte[] randomBytes = new byte[32];
                SECURE_RANDOM.nextBytes(randomBytes);
                String rawResetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

                PasswordResetToken resetToken = PasswordResetToken.builder()
                        .tenantId(tenant.getId())
                        .userId(user.getId())
                        .tokenHash(TokenHashUtil.hash(rawResetToken))
                        .used(false)
                        .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                        .build();
                passwordResetTokenRepository.save(resetToken);

                auditLogService.recordAuditEvent(tenant.getId(), user.getId(), email, "PASSWORD_RESET_REQUESTED", "USER", user.getId().toString(), ipAddress, userAgent, "Issued password reset token");

                return PasswordResetResponse.builder()
                        .message("If an account matches those details, a reset token has been generated.")
                        .resetToken(rawResetToken) // Provided for direct API usage/testing
                        .build();
            }
        }

        // Return same message even if not found to avoid user enumeration
        return PasswordResetResponse.builder()
                .message("If an account matches those details, a reset token has been generated.")
                .resetToken(null)
                .build();
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request, String ipAddress, String userAgent) {
        String tokenHash = TokenHashUtil.hash(request.getResetToken());
        PasswordResetToken resetToken = passwordResetTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid or expired password reset token"));

        if (resetToken.isUsed() || resetToken.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidCredentialsException("Password reset token has already been used or has expired");
        }

        User user = userRepository.findByIdAndTenantId(resetToken.getUserId(), resetToken.getTenantId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found for reset token"));

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);

        // Revoke all sessions
        userSessionRepository.deactivateAllUserSessions(resetToken.getTenantId(), user.getId());
        refreshTokenRepository.revokeAllUserTokens(resetToken.getTenantId(), user.getId(), "PASSWORD_RESET");

        auditLogService.recordAuditEvent(resetToken.getTenantId(), user.getId(), user.getEmail(), "PASSWORD_RESET_COMPLETED", "USER", user.getId().toString(), ipAddress, userAgent, "Password reset completed successfully");
    }

    private void ensureBaselinePermissions() {
        if (permissionRepository.count() == 0) {
            List<Permission> defaults = List.of(
                    Permission.builder().code("USER_READ").description("Read user profiles within tenant").category("USER_MANAGEMENT").build(),
                    Permission.builder().code("USER_CREATE").description("Create new users within tenant").category("USER_MANAGEMENT").build(),
                    Permission.builder().code("USER_UPDATE").description("Update existing users within tenant").category("USER_MANAGEMENT").build(),
                    Permission.builder().code("USER_DELETE").description("Delete or disable users within tenant").category("USER_MANAGEMENT").build(),
                    Permission.builder().code("ROLE_READ").description("View tenant roles and permissions").category("ROLE_MANAGEMENT").build(),
                    Permission.builder().code("ROLE_CREATE").description("Create custom roles within tenant").category("ROLE_MANAGEMENT").build(),
                    Permission.builder().code("ROLE_MANAGE").description("Manage custom roles within tenant").category("ROLE_MANAGEMENT").build(),
                    Permission.builder().code("ROLE_ASSIGN").description("Assign roles to users within tenant").category("ROLE_MANAGEMENT").build(),
                    Permission.builder().code("PERMISSION_READ").description("Read permission catalog").category("ROLE_MANAGEMENT").build(),
                    Permission.builder().code("APPLICATION_READ").description("View registered client applications").category("APPLICATION").build(),
                    Permission.builder().code("APPLICATION_MANAGE").description("Manage registered client applications").category("APPLICATION").build(),
                    Permission.builder().code("AUDIT_READ").description("Read security audit logs").category("AUDIT").build(),
                    Permission.builder().code("TENANT_MANAGE").description("Manage tenant settings").category("TENANT_MANAGEMENT").build(),
                    Permission.builder().code("SECURITY_QUERY_AI").description("Query AI RAG security assistant").category("RAG_AI").build()
            );
            permissionRepository.saveAll(defaults);
        }
    }

    private String parseDeviceInfo(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown Device";
        if (userAgent.contains("Postman")) return "Postman Runtime";
        if (userAgent.contains("Chrome")) return "Chrome Browser";
        if (userAgent.contains("Firefox")) return "Firefox Browser";
        if (userAgent.contains("Safari")) return "Safari Browser";
        if (userAgent.contains("Edge")) return "Edge Browser";
        return userAgent.length() > 50 ? userAgent.substring(0, 50) : userAgent;
    }
}
