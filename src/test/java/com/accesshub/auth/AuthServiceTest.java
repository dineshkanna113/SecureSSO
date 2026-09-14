package com.accesshub.auth;

import com.accesshub.audit.AuditLogService;
import com.accesshub.auth.dto.*;
import com.accesshub.exception.InvalidCredentialsException;
import com.accesshub.permission.Permission;
import com.accesshub.permission.PermissionRepository;
import com.accesshub.role.Role;
import com.accesshub.role.RoleRepository;
import com.accesshub.security.JwtTokenProvider;
import com.accesshub.tenant.Tenant;
import com.accesshub.tenant.TenantRepository;
import com.accesshub.user.User;
import com.accesshub.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private TenantRepository tenantRepository;
    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserSessionRepository userSessionRepository;
    @Mock private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private TokenRevocationService tokenRevocationService;
    @Mock private LoginRateLimiterService loginRateLimiterService;
    @Mock private AuditLogService auditLogService;

    @InjectMocks
    private AuthService authService;

    private UUID tenantId;
    private Tenant tenant;
    private User user;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        tenant = Tenant.builder()
                .id(tenantId)
                .name("Acme Corp")
                .slug("acme")
                .status(Tenant.TenantStatus.ACTIVE)
                .build();

        user = User.builder()
                .id(UUID.randomUUID())
                .tenantId(tenantId)
                .email("admin@acme.com")
                .passwordHash("hashed_pass")
                .enabled(true)
                .locked(false)
                .roles(Set.of(Role.builder().name("TENANT_ADMIN").permissions(Set.of(
                        Permission.builder().code("USER_READ").category("USER").build()
                )).build()))
                .build();
    }

    @Test
    void registerTenant_Success() {
        RegisterTenantRequest request = new RegisterTenantRequest();
        request.setTenantName("Acme Corp");
        request.setTenantSlug("acme");
        request.setAdminEmail("admin@acme.com");
        request.setAdminPassword("password123");

        when(tenantRepository.existsBySlug("acme")).thenReturn(false);
        when(tenantRepository.save(any(Tenant.class))).thenReturn(tenant);
        when(permissionRepository.count()).thenReturn(10L);
        when(permissionRepository.findAll()).thenReturn(List.of());
        when(roleRepository.save(any(Role.class))).thenAnswer(i -> i.getArgument(0));
        when(passwordEncoder.encode("password123")).thenReturn("hashed_pass");
        when(userRepository.save(any(User.class))).thenReturn(user);

        RegisterTenantResponse response = authService.registerTenant(request, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertEquals(tenantId, response.getTenantId());
        assertEquals("acme", response.getTenantSlug());
        verify(auditLogService, times(1)).recordAuditEvent(any(), any(), any(), eq("TENANT_REGISTERED"), any(), any(), any(), any(), any());
    }

    @Test
    void login_Success() {
        LoginRequest request = new LoginRequest();
        request.setTenantSlug("acme");
        request.setEmail("admin@acme.com");
        request.setPassword("password123");

        when(loginRateLimiterService.isIpRateLimited(anyString())).thenReturn(false);
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(tenant));
        when(loginRateLimiterService.isAccountLocked(any(), anyString())).thenReturn(false);
        when(userRepository.findByEmailAndTenantId("admin@acme.com", tenantId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "hashed_pass")).thenReturn(true);
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(i -> {
            UserSession s = i.getArgument(0);
            s.setId(UUID.randomUUID());
            return s;
        });
        when(jwtTokenProvider.generateAccessToken(any(), any(), any(), any(), any())).thenReturn("mock_access_token");
        when(jwtTokenProvider.generateRefreshToken(any(), any(), any(), any(), any(), anyInt())).thenReturn("mock_refresh_token");

        LoginResponse response = authService.login(request, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertEquals("mock_access_token", response.getAccessToken());
        assertEquals("mock_refresh_token", response.getRefreshToken());
        verify(loginRateLimiterService, times(1)).resetAttempts(tenantId, "admin@acme.com");
        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    }

    @Test
    void login_InvalidPassword_ThrowsException() {
        LoginRequest request = new LoginRequest();
        request.setTenantSlug("acme");
        request.setEmail("admin@acme.com");
        request.setPassword("wrongpass");

        when(loginRateLimiterService.isIpRateLimited(anyString())).thenReturn(false);
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(tenant));
        when(loginRateLimiterService.isAccountLocked(any(), anyString())).thenReturn(false);
        when(userRepository.findByEmailAndTenantId("admin@acme.com", tenantId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongpass", "hashed_pass")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, "127.0.0.1", "TestAgent"));
        verify(loginRateLimiterService, times(1)).recordFailedAttempt(tenantId, "127.0.0.1", "admin@acme.com");
    }
}
