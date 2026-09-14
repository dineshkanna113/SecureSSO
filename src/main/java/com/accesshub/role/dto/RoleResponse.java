package com.accesshub.role.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleResponse {
    private UUID id;
    private UUID tenantId;
    private String name;
    private String description;
    private boolean isSystemRole;
    private Set<String> permissions;
    private Instant createdAt;
}
