package com.accesshub.application;

import com.accesshub.application.dto.*;
import com.accesshub.security.ClientInfoResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/applications")
@RequiredArgsConstructor
@SecurityRequirement(name = "Bearer Authentication")
@Tag(name = "OAuth / Client Application Management", description = "Tenant client application registration, redirect URI validation, secret rotation, and status management APIs")
public class ApplicationController {

    private final ApplicationService applicationService;
    private final ClientInfoResolver clientInfoResolver;

    @GetMapping
    @PreAuthorize("hasAuthority('APPLICATION_READ') or hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "List Client Applications", description = "Retrieves registered applications for the tenant.")
    public ResponseEntity<Page<ApplicationResponse>> getApplications(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(applicationService.getApplications(PageRequest.of(page, size, Sort.by("createdAt").descending())));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('APPLICATION_READ') or hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "Get Application Details", description = "Retrieves details of a tenant registered client application.")
    public ResponseEntity<ApplicationResponse> getApplicationById(@PathVariable UUID id) {
        return ResponseEntity.ok(applicationService.getApplicationById(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "Register Client Application", description = "Registers a new OAuth client application, validating redirect URIs strictly and returning client_id and raw client_secret once.")
    public ResponseEntity<ApplicationResponse> createApplication(
            @Valid @RequestBody CreateApplicationRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return new ResponseEntity<>(applicationService.createApplication(request, ip, userAgent), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "Update Client Application", description = "Updates application name, allowed scopes, and validated redirect URIs.")
    public ResponseEntity<ApplicationResponse> updateApplication(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateApplicationRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(applicationService.updateApplication(id, request, ip, userAgent));
    }

    @PostMapping("/{id}/rotate-secret")
    @PreAuthorize("hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "Rotate Client Secret", description = "Generates a new client secret for the application, invalidating the previous secret.")
    public ResponseEntity<ApplicationResponse> rotateSecret(
            @PathVariable UUID id,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(applicationService.rotateSecret(id, ip, userAgent));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAuthority('APPLICATION_MANAGE')")
    @Operation(summary = "Update Application Status", description = "Enables, disables, or suspends a registered client application.")
    public ResponseEntity<ApplicationResponse> updateStatus(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateApplicationStatusRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(applicationService.updateStatus(id, request, ip, userAgent));
    }
}
