package com.accesshub.rag.dto;

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
public class SecurityPolicyResponse {
    private UUID id;
    private UUID tenantId;
    private String title;
    private String category;
    private String content;
    private String tags;
    private Instant createdAt;
}
