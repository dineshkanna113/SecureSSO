package com.accesshub.auth;

import com.accesshub.auth.dto.*;
import com.accesshub.security.ClientInfoResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication & Sessions", description = "Tenant onboarding, user authentication, token family rotation, logout, and password recovery APIs")
public class AuthController {

    private final AuthService authService;
    private final ClientInfoResolver clientInfoResolver;

    @PostMapping("/register")
    @Operation(summary = "Register Tenant & Super Admin", description = "Onboards a new organization tenant and initializes its Super Admin user with default roles.")
    public ResponseEntity<RegisterTenantResponse> registerTenant(
            @Valid @RequestBody RegisterTenantRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        RegisterTenantResponse response = authService.registerTenant(request, ip, userAgent);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    @Operation(summary = "User Authentication", description = "Validates credentials within a tenant, enforces dual-bucket rate limiting, creates a user session, and issues a JWT token pair.")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        LoginResponse response = authService.login(request, ip, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh Token Rotation", description = "Exchanges a valid refresh token for a new token pair using token family rotation. Detects token reuse and revokes compromised families.")
    public ResponseEntity<LoginResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        LoginResponse response = authService.refreshToken(request, ip, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "User Logout", description = "Revokes current refresh token and deactivates the current user session.")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody LogoutRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        authService.logout(request, ip, userAgent);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Logout All Sessions", description = "Revokes all refresh tokens and terminates all active sessions for the authenticated user.")
    public ResponseEntity<Void> logoutAll(HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        authService.logoutAll(ip, userAgent);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change Password", description = "Changes authenticated user password, validates password complexity, and revokes all active sessions.")
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        authService.changePassword(request, ip, userAgent);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request Password Reset", description = "Initiates self-service password reset with single-use reset token. Resistant to user enumeration.")
    public ResponseEntity<PasswordResetResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        PasswordResetResponse response = authService.forgotPassword(request, ip, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset Password with Token", description = "Resets user password using single-use reset token and invalidates all existing sessions.")
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        authService.resetPassword(request, ip, userAgent);
        return ResponseEntity.noContent().build();
    }
}
