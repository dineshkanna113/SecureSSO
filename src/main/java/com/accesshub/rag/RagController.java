package com.accesshub.rag;

import com.accesshub.rag.dto.*;
import com.accesshub.security.ClientInfoResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/rag")
@RequiredArgsConstructor
@SecurityRequirement(name = "Bearer Authentication")
@Tag(name = "AI RAG IAM & Security Assistant", description = "Tenant-isolated AI vector security query and compliance policy knowledge base APIs")
public class RagController {

    private final RagSecurityAssistantService ragService;
    private final ClientInfoResolver clientInfoResolver;

    @PostMapping("/security-query")
    @PreAuthorize("hasAuthority('SECURITY_QUERY_AI')")
    @Operation(summary = "Ask AI IAM Assistant", description = "Performs tenant-isolated RAG security query matching policies and recent audit logs for security posture analysis.")
    public ResponseEntity<SecurityQueryResponse> askSecurityAssistant(
            @Valid @RequestBody SecurityQueryRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        SecurityQueryResponse response = ragService.processSecurityQuery(request, ip, userAgent);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/policies")
    @PreAuthorize("hasAuthority('SECURITY_QUERY_AI')")
    @Operation(summary = "List Knowledge Base Policies", description = "Lists tenant security policies used by RAG LLM vector search.")
    public ResponseEntity<List<SecurityPolicyResponse>> getPolicies() {
        return ResponseEntity.ok(ragService.getTenantPolicies());
    }

    @PostMapping("/policies")
    @PreAuthorize("hasAuthority('SECURITY_QUERY_AI')")
    @Operation(summary = "Add Security Policy Document", description = "Ingests a custom security policy document into the tenant's RAG knowledge base.")
    public ResponseEntity<SecurityPolicyResponse> addPolicy(@Valid @RequestBody SecurityPolicyRequest request) {
        return new ResponseEntity<>(ragService.createPolicy(request), HttpStatus.CREATED);
    }
}
