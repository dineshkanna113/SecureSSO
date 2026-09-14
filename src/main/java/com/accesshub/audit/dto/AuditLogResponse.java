package com.accesshub.audit.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogResponse {
    private UUID id;
    private UUID tenantId;
    private UUID actorId;
    private String actorEmail;
    private String action;
    private String resourceType;
    private String resourceId;
    private String correlationId;
    private String ipAddress;
    private String userAgent;
    private String metadata;
    private Instant timestamp;
}
