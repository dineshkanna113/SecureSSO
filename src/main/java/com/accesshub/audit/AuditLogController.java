package com.accesshub.audit;

import com.accesshub.audit.dto.AuditLogResponse;
import com.accesshub.exception.TenantAccessDeniedException;
import com.accesshub.tenant.TenantContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
@SecurityRequirement(name = "Bearer Authentication")
@Tag(name = "Security Audit Logging", description = "Tenant security audit logs and event history query APIs")
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasAuthority('AUDIT_READ')")
    @Operation(summary = "Search Audit Logs", description = "Retrieves paginated audit log events for the caller's tenant with filtering options.")
    public ResponseEntity<Page<AuditLogResponse>> getAuditLogs(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) UUID actorId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }

        Page<AuditLogResponse> auditLogs = auditLogService.getTenantAuditLogs(
                tenantId, action, actorId, PageRequest.of(page, size, Sort.by("timestamp").descending()));
        return ResponseEntity.ok(auditLogs);
    }
}
