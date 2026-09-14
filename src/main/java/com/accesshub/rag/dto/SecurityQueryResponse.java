package com.accesshub.rag.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityQueryResponse {
    private UUID tenantId;
    private String query;
    private String aiAnalysis;
    private List<String> retrievedPolicyTitles;
    private int auditLogsAnalyzedCount;
    private List<String> keyRecommendations;
    private String executionMode; // "LIVE_LLM" or "LOCAL_RAG_ENGINE"
}
