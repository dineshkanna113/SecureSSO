package com.accesshub.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterTenantResponse {
    private UUID tenantId;
    private String tenantName;
    private String tenantSlug;
    private UUID adminUserId;
    private String adminEmail;
    private String message;
}
