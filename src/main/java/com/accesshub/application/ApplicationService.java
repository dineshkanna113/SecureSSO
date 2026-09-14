package com.accesshub.application;

import com.accesshub.application.dto.*;
import com.accesshub.audit.AuditLogService;
import com.accesshub.exception.ResourceNotFoundException;
import com.accesshub.exception.TenantAccessDeniedException;
import com.accesshub.tenant.TenantContext;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ApplicationService {

    private final ApplicationRepository applicationRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;
    private final RedirectUriValidator redirectUriValidator;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional(readOnly = true)
    public Page<ApplicationResponse> getApplications(Pageable pageable) {
        UUID tenantId = requireTenantContext();
        return applicationRepository.findByTenantId(tenantId, pageable)
                .map(app -> mapToResponse(app, null));
    }

    @Transactional(readOnly = true)
    public ApplicationResponse getApplicationById(UUID id) {
        UUID tenantId = requireTenantContext();
        Application app = applicationRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Application not found for ID: " + id));
        return mapToResponse(app, null);
    }

    @Transactional
    public ApplicationResponse createApplication(CreateApplicationRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();

        // Strict RFC 3986 Redirect URI validation to prevent open redirects
        redirectUriValidator.validateRedirectUris(request.getRedirectUris());

        String clientId = "client_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String rawSecret = generateSecureSecret();
        String secretHash = passwordEncoder.encode(rawSecret);

        Application app = Application.builder()
                .tenantId(tenantId)
                .name(request.getName().trim())
                .clientId(clientId)
                .clientSecretHash(secretHash)
                .redirectUris(request.getRedirectUris())
                .allowedScopes(request.getAllowedScopes() != null ? request.getAllowedScopes() : "openid profile email")
                .status(Application.ApplicationStatus.ACTIVE)
                .build();

        app = applicationRepository.save(app);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "APPLICATION_CREATED", "APPLICATION", app.getId().toString(), ip, userAgent, "Registered application '" + app.getName() + "'");

        return mapToResponse(app, rawSecret);
    }

    @Transactional
    public ApplicationResponse updateApplication(UUID id, UpdateApplicationRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        Application app = applicationRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Application not found for ID: " + id));

        redirectUriValidator.validateRedirectUris(request.getRedirectUris());

        app.setName(request.getName().trim());
        if (request.getRedirectUris() != null) {
            app.setRedirectUris(request.getRedirectUris().trim());
        }
        if (request.getAllowedScopes() != null) {
            app.setAllowedScopes(request.getAllowedScopes().trim());
        }

        app = applicationRepository.save(app);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "APPLICATION_UPDATED", "APPLICATION", app.getId().toString(), ip, userAgent, "Updated application settings for '" + app.getName() + "'");

        return mapToResponse(app, null);
    }

    @Transactional
    public ApplicationResponse rotateSecret(UUID id, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        Application app = applicationRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Application not found for ID: " + id));

        String newRawSecret = generateSecureSecret();
        app.setClientSecretHash(passwordEncoder.encode(newRawSecret));
        app = applicationRepository.save(app);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "CLIENT_SECRET_ROTATED", "APPLICATION", app.getId().toString(), ip, userAgent, "Rotated secret for application '" + app.getName() + "'");

        return mapToResponse(app, newRawSecret);
    }

    @Transactional
    public ApplicationResponse updateStatus(UUID id, UpdateApplicationStatusRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        Application app = applicationRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Application not found for ID: " + id));

        app.setStatus(request.getStatus());
        app = applicationRepository.save(app);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "APPLICATION_STATUS_UPDATED", "APPLICATION", app.getId().toString(), ip, userAgent, "Updated status to " + request.getStatus());

        return mapToResponse(app, null);
    }

    private String generateSecureSecret() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private UUID requireTenantContext() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }
        return tenantId;
    }

    private ApplicationResponse mapToResponse(Application app, String cleartextSecret) {
        return ApplicationResponse.builder()
                .id(app.getId())
                .tenantId(app.getTenantId())
                .name(app.getName())
                .clientId(app.getClientId())
                .clientSecret(cleartextSecret)
                .redirectUris(app.getRedirectUris())
                .allowedScopes(app.getAllowedScopes())
                .status(app.getStatus())
                .createdAt(app.getCreatedAt())
                .updatedAt(app.getUpdatedAt())
                .build();
    }
}
