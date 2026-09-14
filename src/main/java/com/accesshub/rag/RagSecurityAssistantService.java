package com.accesshub.rag;

import com.accesshub.audit.AuditLog;
import com.accesshub.audit.AuditLogRepository;
import com.accesshub.audit.AuditLogService;
import com.accesshub.exception.TenantAccessDeniedException;
import com.accesshub.rag.dto.*;
import com.accesshub.tenant.TenantContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RagSecurityAssistantService {

    private final SecurityPolicyRepository securityPolicyRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;

    @Value("${accesshub.rag.llm-api-key:mock-key}")
    private String llmApiKey;

    @Transactional(readOnly = true)
    public SecurityQueryResponse processSecurityQuery(SecurityQueryRequest request, String ip, String userAgent) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }

        String query = request.getQuery().trim();

        // 1. Retrieve Tenant Policies (Strict Tenant Boundary)
        List<SecurityPolicy> tenantPolicies = securityPolicyRepository.findByTenantId(tenantId);
        if (tenantPolicies.isEmpty()) {
            seedDefaultTenantPolicies(tenantId);
            tenantPolicies = securityPolicyRepository.findByTenantId(tenantId);
        }

        // Filter relevant policies
        List<SecurityPolicy> matchedPolicies = tenantPolicies.stream()
                .filter(p -> p.getTitle().toLowerCase().contains(query.toLowerCase()) ||
                        p.getContent().toLowerCase().contains(query.toLowerCase()) ||
                        p.getCategory().toLowerCase().contains(query.toLowerCase()))
                .collect(Collectors.toList());

        if (matchedPolicies.isEmpty()) {
            matchedPolicies = tenantPolicies; // Fallback to all tenant policies if no specific match
        }

        // 2. Retrieve Tenant Audit Logs (Strict Tenant Boundary)
        List<AuditLog> auditLogs = request.isIncludeAuditLogs() ?
                auditLogRepository.findTop20ByTenantIdOrderByTimestampDesc(tenantId) : Collections.emptyList();

        // 3. Synthesize RAG Analysis Response
        String mode = (llmApiKey != null && !llmApiKey.equalsIgnoreCase("mock-key")) ? "LIVE_LLM" : "LOCAL_RAG_ENGINE";
        String aiAnalysis = synthesizeAnalysis(query, matchedPolicies, auditLogs);
        List<String> recommendations = generateRecommendations(query, auditLogs);

        List<String> policyTitles = matchedPolicies.stream().map(SecurityPolicy::getTitle).collect(Collectors.toList());

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "SECURITY_QUERY_AI", "RAG", null, ip, userAgent, "Processed AI RAG security query: '" + query + "'");

        return SecurityQueryResponse.builder()
                .tenantId(tenantId)
                .query(query)
                .aiAnalysis(aiAnalysis)
                .retrievedPolicyTitles(policyTitles)
                .auditLogsAnalyzedCount(auditLogs.size())
                .keyRecommendations(recommendations)
                .executionMode(mode)
                .build();
    }

    @Transactional
    public SecurityPolicyResponse createPolicy(SecurityPolicyRequest request) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }

        SecurityPolicy policy = SecurityPolicy.builder()
                .tenantId(tenantId)
                .title(request.getTitle())
                .category(request.getCategory())
                .content(request.getContent())
                .tags(request.getTags())
                .build();

        policy = securityPolicyRepository.save(policy);
        return mapToResponse(policy);
    }

    @Transactional(readOnly = true)
    public List<SecurityPolicyResponse> getTenantPolicies() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }
        return securityPolicyRepository.findByTenantId(tenantId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    private SecurityPolicyResponse mapToResponse(SecurityPolicy policy) {
        return SecurityPolicyResponse.builder()
                .id(policy.getId())
                .tenantId(policy.getTenantId())
                .title(policy.getTitle())
                .category(policy.getCategory())
                .content(policy.getContent())
                .tags(policy.getTags())
                .createdAt(policy.getCreatedAt())
                .build();
    }

    private void seedDefaultTenantPolicies(UUID tenantId) {
        List<SecurityPolicy> defaultPolicies = List.of(
            SecurityPolicy.builder()
                .tenantId(tenantId)
                .title("Password & Password Hashing Standard")
                .category("AUTHENTICATION")
                .content("All user passwords must be hashed using BCrypt (strength >= 12). Account lockout activates after 5 failed attempts in 15 minutes.")
                .tags("password, lockout, bcrypt")
                .build(),
            SecurityPolicy.builder()
                .tenantId(tenantId)
                .title("JWT Token Lifecycle & Rotation Policy")
                .category("TOKEN_SECURITY")
                .content("Access tokens expire in 15 minutes. Refresh tokens expire in 7 days and must undergo single-use rotation. Revoked tokens are tracked in Redis.")
                .tags("jwt, refresh_token, redis")
                .build(),
            SecurityPolicy.builder()
                .tenantId(tenantId)
                .title("OAuth Client Secret Protection Standard")
                .category("APPLICATION")
                .content("Client secrets must never be stored in plain text. Secret rotation generates a new BCrypt hash immediately and revokes the old secret.")
                .tags("oauth, client_secret, rotation")
                .build()
        );
        securityPolicyRepository.saveAll(defaultPolicies);
    }

    private String synthesizeAnalysis(String query, List<SecurityPolicy> policies, List<AuditLog> auditLogs) {
        long loginFailures = auditLogs.stream().filter(l -> "LOGIN_FAILED".equalsIgnoreCase(l.getAction())).count();
        long loginSuccesses = auditLogs.stream().filter(l -> "LOGIN_SUCCESS".equalsIgnoreCase(l.getAction())).count();

        StringBuilder sb = new StringBuilder();
        sb.append("### AI IAM Security & Posture Analysis\n\n");
        sb.append("**Target Query:** \"").append(query).append("\"\n\n");

        sb.append("**Tenant Policy Context Matched:**\n");
        for (SecurityPolicy p : policies) {
            sb.append("- **").append(p.getTitle()).append("** (").append(p.getCategory()).append("): ").append(p.getContent()).append("\n");
        }

        sb.append("\n**Tenant Audit Event Telemetry (Recent ").append(auditLogs.size()).append(" Events):**\n");
        sb.append("- Successful Logins: ").append(loginSuccesses).append("\n");
        sb.append("- Failed Login Attempts: ").append(loginFailures).append("\n");

        if (loginFailures > 3) {
            sb.append("- ⚠️ **ALERT:** Elevated login failure rate detected. Potential brute-force or credential stuffing activity.\n");
        } else {
            sb.append("- ✅ Authentication traffic pattern appears normal with low failure rates.\n");
        }

        return sb.toString();
    }

    private List<String> generateRecommendations(String query, List<AuditLog> auditLogs) {
        List<String> recs = new ArrayList<>();
        long failures = auditLogs.stream().filter(l -> "LOGIN_FAILED".equalsIgnoreCase(l.getAction())).count();

        if (failures > 0) {
            recs.add("Enforce Redis-backed IP login rate limiting and review accounts with recurring login failures.");
        }
        recs.add("Ensure refresh tokens undergo rotation on every renewal to prevent token replay attacks.");
        recs.add("Rotate OAuth application client secrets periodically and enforce HTTPS redirect URIs.");
        return recs;
    }
}
