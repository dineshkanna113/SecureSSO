package com.accesshub.rag.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SecurityQueryRequest {

    @NotBlank(message = "Query text is required")
    private String query;

    private boolean includeAuditLogs = true;
    private boolean includePolicies = true;
}
