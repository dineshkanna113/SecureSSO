package com.accesshub.user;

import com.accesshub.audit.AuditLogService;
import com.accesshub.exception.ResourceNotFoundException;
import com.accesshub.exception.TenantAccessDeniedException;
import com.accesshub.permission.Permission;
import com.accesshub.role.Role;
import com.accesshub.role.RoleRepository;
import com.accesshub.tenant.TenantContext;
import com.accesshub.user.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    @Transactional(readOnly = true)
    public Page<UserResponse> getUsers(Pageable pageable) {
        UUID tenantId = requireTenantContext();
        return userRepository.findByTenantId(tenantId, pageable)
                .map(this::mapToUserResponse);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID userId) {
        UUID tenantId = requireTenantContext();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for ID: " + userId));
        return mapToUserResponse(user);
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        String email = request.getEmail().toLowerCase().trim();

        if (userRepository.existsByEmailAndTenantId(email, tenantId)) {
            throw new IllegalArgumentException("User with email '" + email + "' already exists in this tenant");
        }

        Set<Role> roles = new HashSet<>();
        if (request.getRoleNames() != null && !request.getRoleNames().isEmpty()) {
            for (String roleName : request.getRoleNames()) {
                Role role = roleRepository.findByNameAndTenantId(roleName, tenantId)
                        .orElseThrow(() -> new ResourceNotFoundException("Role '" + roleName + "' not found in tenant"));
                roles.add(role);
            }
        } else {
            Role defaultRole = roleRepository.findByNameAndTenantId("USER", tenantId)
                    .orElseGet(() -> roleRepository.save(Role.builder()
                            .tenantId(tenantId)
                            .name("USER")
                            .description("Default tenant user")
                            .isSystemRole(true)
                            .build()));
            roles.add(defaultRole);
        }

        User user = User.builder()
                .tenantId(tenantId)
                .email(email)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(true)
                .locked(false)
                .roles(roles)
                .build();

        user = userRepository.save(user);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "USER_CREATED", "USER", user.getId().toString(), ip, userAgent, "Created user " + email);

        return mapToUserResponse(user);
    }

    @Transactional
    public UserResponse updateUser(UUID userId, UpdateUserRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for ID: " + userId));

        if (request.getFirstName() != null) user.setFirstName(request.getFirstName());
        if (request.getLastName() != null) user.setLastName(request.getLastName());
        if (request.getEnabled() != null) user.setEnabled(request.getEnabled());
        if (request.getLocked() != null) user.setLocked(request.getLocked());

        user = userRepository.save(user);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "USER_UPDATED", "USER", user.getId().toString(), ip, userAgent, "Updated user profile");

        return mapToUserResponse(user);
    }

    @Transactional
    public void deleteUser(UUID userId, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for ID: " + userId));

        userRepository.delete(user);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "USER_DELETED", "USER", userId.toString(), ip, userAgent, "Deleted user " + user.getEmail());
    }

    @Transactional
    public UserResponse assignRoles(UUID userId, AssignRolesRequest request, String ip, String userAgent) {
        UUID tenantId = requireTenantContext();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for ID: " + userId));

        Set<Role> newRoles = new HashSet<>();
        for (String roleName : request.getRoleNames()) {
            Role role = roleRepository.findByNameAndTenantId(roleName, tenantId)
                    .orElseThrow(() -> new ResourceNotFoundException("Role '" + roleName + "' not found in tenant"));
            newRoles.add(role);
        }

        user.setRoles(newRoles);
        user = userRepository.save(user);

        auditLogService.recordAuditEvent(
                tenantId, TenantContext.getUserId(), null, "ROLE_ASSIGNED", "USER", user.getId().toString(), ip, userAgent, "Assigned roles: " + request.getRoleNames());

        return mapToUserResponse(user);
    }

    private UUID requireTenantContext() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new TenantAccessDeniedException("Tenant context missing or invalid");
        }
        return tenantId;
    }

    private UserResponse mapToUserResponse(User user) {
        Set<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        Set<String> authorities = new HashSet<>();
        for (Role r : user.getRoles()) {
            for (Permission p : r.getPermissions()) {
                authorities.add(p.getCode());
            }
        }

        return UserResponse.builder()
                .id(user.getId())
                .tenantId(user.getTenantId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .enabled(user.isEnabled())
                .locked(user.isLocked())
                .roles(roleNames)
                .permissions(authorities)
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
