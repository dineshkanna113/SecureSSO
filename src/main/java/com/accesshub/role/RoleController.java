package com.accesshub.role;

import com.accesshub.role.dto.*;
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
import java.util.UUID;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
@SecurityRequirement(name = "Bearer Authentication")
@Tag(name = "Role & RBAC Management", description = "Tenant-scoped role creation, listing, permission attachment, and deletion APIs")
public class RoleController {

    private final RoleService roleService;
    private final ClientInfoResolver clientInfoResolver;

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "List Tenant Roles", description = "Retrieves all custom and system roles defined within the caller's tenant.")
    public ResponseEntity<List<RoleResponse>> getRoles() {
        return ResponseEntity.ok(roleService.getRoles());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "Get Role by ID", description = "Retrieves a tenant role by ID.")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable UUID id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_CREATE') or hasAuthority('ROLE_MANAGE')")
    @Operation(summary = "Create Custom Role", description = "Creates a new custom RBAC role with assigned permissions for the tenant.")
    public ResponseEntity<RoleResponse> createRole(
            @Valid @RequestBody CreateRoleRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return new ResponseEntity<>(roleService.createRole(request, ip, userAgent), HttpStatus.CREATED);
    }

    @PostMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @Operation(summary = "Update Role Permissions", description = "Updates or replaces the set of permissions attached to a tenant role.")
    public ResponseEntity<RoleResponse> assignPermissionsToRole(
            @PathVariable UUID id,
            @Valid @RequestBody AssignPermissionsRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(roleService.assignPermissionsToRole(id, request, ip, userAgent));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @Operation(summary = "Delete Custom Role", description = "Removes a non-system role from the caller's tenant.")
    public ResponseEntity<Void> deleteRole(
            @PathVariable UUID id,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        roleService.deleteRole(id, ip, userAgent);
        return ResponseEntity.noContent().build();
    }
}
