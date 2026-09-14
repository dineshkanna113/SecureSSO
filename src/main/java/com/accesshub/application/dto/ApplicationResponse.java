package com.accesshub.application.dto;

import com.accesshub.application.Application;
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
public class ApplicationResponse {
    private UUID id;
    private UUID tenantId;
    private String name;
    private String clientId;
    private String clientSecret; // Present only on creation / rotation
    private String redirectUris;
    private String allowedScopes;
    private Application.ApplicationStatus status;
    private Instant createdAt;
    private Instant updatedAt;
}
