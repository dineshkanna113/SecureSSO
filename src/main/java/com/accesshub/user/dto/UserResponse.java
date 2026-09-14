package com.accesshub.user.dto;

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
public class UserResponse {
    private UUID id;
    private UUID tenantId;
    private String email;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private boolean locked;
    private Set<String> roles;
    private Set<String> permissions;
    private Instant createdAt;
    private Instant updatedAt;
}
