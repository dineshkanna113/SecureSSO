package com.accesshub.audit;

import com.accesshub.audit.dto.AuditLogResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public void recordAuditEvent(
            UUID tenantId,
            UUID actorId,
            String actorEmail,
            String action,
            String resourceType,
            String resourceId,
            String ipAddress,
            String userAgent,
            String metadata) {
        String correlationId = MDC.get("correlationId");
        recordAuditEvent(tenantId, actorId, actorEmail, action, resourceType, resourceId, correlationId, ipAddress, userAgent, metadata);
    }

    @Async
    @Transactional
    public void recordAuditEvent(
            UUID tenantId,
            UUID actorId,
            String actorEmail,
            String action,
            String resourceType,
            String resourceId,
            String correlationId,
            String ipAddress,
            String userAgent,
            String metadata) {

        if (tenantId == null) {
            log.warn("Recording audit event '{}' without tenant ID (actor: {}, ip: {})", action, actorEmail, ipAddress);
            return;
        }

        try {
            AuditLog auditLog = AuditLog.builder()
                    .tenantId(tenantId)
                    .actorId(actorId)
                    .actorEmail(actorEmail)
                    .action(action)
                    .resourceType(resourceType)
                    .resourceId(resourceId)
                    .correlationId(correlationId)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .metadata(metadata)
                    .timestamp(Instant.now())
                    .build();

            auditLogRepository.save(auditLog);
            log.debug("Recorded audit log: [{}] tenant={}, action={}, correlationId={}, actor={}", 
                    auditLog.getId(), tenantId, action, correlationId, actorEmail);
        } catch (Exception e) {
            log.error("Failed to write audit log event: {}", e.getMessage(), e);
        }
    }

    @Transactional(readOnly = true)
    public Page<AuditLogResponse> getTenantAuditLogs(UUID tenantId, String action, UUID actorId, Pageable pageable) {
        return auditLogRepository.findByTenantIdFiltered(tenantId, action, actorId, pageable)
                .map(this::mapToResponse);
    }

    @Transactional(readOnly = true)
    public List<AuditLogResponse> getRecentTenantLogs(UUID tenantId) {
        return auditLogRepository.findTop20ByTenantIdOrderByTimestampDesc(tenantId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public AuditLogResponse mapToResponse(AuditLog auditLog) {
        return AuditLogResponse.builder()
                .id(auditLog.getId())
                .tenantId(auditLog.getTenantId())
                .actorId(auditLog.getActorId())
                .actorEmail(auditLog.getActorEmail())
                .action(auditLog.getAction())
                .resourceType(auditLog.getResourceType())
                .resourceId(auditLog.getResourceId())
                .correlationId(auditLog.getCorrelationId())
                .ipAddress(auditLog.getIpAddress())
                .userAgent(auditLog.getUserAgent())
                .metadata(auditLog.getMetadata())
                .timestamp(auditLog.getTimestamp())
                .build();
    }
}
