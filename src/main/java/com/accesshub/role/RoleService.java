package com.accesshub.role;

import com.accesshub.audit.AuditLogService;
import com.accesshub.exception.ResourceNotFoundException;
import com.accesshub.exception.TenantAccessDeniedException;
import com.accesshub.permission.Permission;
import com.accesshub.permission.PermissionRepository;
import com.accesshub.role.dto.*;
import com.accesshub.tenant.TenantContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final AuditLogService auditLogService;

    @Transactional(readOnly = true)
    public List<RoleResponse> getRoles() {
        UUID tenantId = requireTenantContext();
        return roleRepository.findByTenantId(tenantId).stream()
                .map(this::mapToRoleResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public RoleResponse getRoleById(UUID id) {
        UUID tenantId = requireTenantContext();
        Role role = roleRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found for ID: " + id));
        return mapToRoleResponse(role);
    }

    @Transactional
    public RoleResponse createRole(CreateRoleRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        String name = request.getName().trim().toUpperCase();

        if (roleRepository.existsByNameAndTenantId(name, tenantId)) {
            throw new IllegalArgumentException("Role with name '" + name + "' already exists in this tenant");
        }

        Set<Permission> permissions = new HashSet<>();
        if (request.getPermissionCodes() != null && !request.getPermissionCodes().isEmpty()) {
            permissions = permissionRepository.findByCodeIn(request.getPermissionCodes());
        }

        Role role = Role.builder()
                .tenantId(tenantId)
                .name(name)
                .description(request.getDescription())
                .isSystemRole(false)
                .permissions(permissions)
                .build();

        role = roleRepository.save(role);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "ROLE_CREATED", "ROLE", role.getId().toString(), ip, userAgent, "Created role " + name);

        return mapToRoleResponse(role);
    }

    @Transactional
    public RoleResponse assignPermissionsToRole(UUID roleId, AssignPermissionsRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        Role role = roleRepository.findByIdAndTenantId(roleId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found for ID: " + roleId));

        Set<Permission> permissions = permissionRepository.findByCodeIn(request.getPermissionCodes());
        role.setPermissions(permissions);
        role = roleRepository.save(role);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "ROLE_PERMISSIONS_UPDATED", "ROLE", role.getId().toString(), ip, userAgent, "Updated permissions for role " + role.getName());

        return mapToRoleResponse(role);
    }

    @Transactional
    public void deleteRole(UUID roleId, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        Role role = roleRepository.findByIdAndTenantId(roleId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found for ID: " + roleId));

        if (role.isSystemRole()) {
            throw new IllegalArgumentException("System default roles cannot be deleted");
        }

        roleRepository.delete(role);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "ROLE_DELETED", "ROLE", roleId.toString(), ip, userAgent, "Deleted role " + role.getName());
    }

    private UUID requireTenantContext() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }
        return tenantId;
    }

    private RoleResponse mapToRoleResponse(Role role) {
        Set<String> permCodes = role.getPermissions().stream()
                .map(Permission::getCode)
                .collect(Collectors.toSet());

        return RoleResponse.builder()
                .id(role.getId())
                .tenantId(role.getTenantId())
                .name(role.getName())
                .description(role.getDescription())
                .isSystemRole(role.isSystemRole())
                .permissions(permCodes)
                .createdAt(role.getCreatedAt())
                .build();
    }
}
