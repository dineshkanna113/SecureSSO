package com.accesshub.user;

import com.accesshub.security.ClientInfoResolver;
import com.accesshub.user.dto.*;
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
@RequestMapping("/api/users")
@RequiredArgsConstructor
@SecurityRequirement(name = "Bearer Authentication")
@Tag(name = "User Management", description = "Tenant-scoped user management, role assignment, and profile APIs")
public class UserController {

    private final UserService userService;
    private final ClientInfoResolver clientInfoResolver;

    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "List Users", description = "Retrieves paginated user profiles belonging strictly to the caller's tenant.")
    public ResponseEntity<Page<UserResponse>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String direction) {

        // Validate sortBy field to prevent injection/500 errors
        String safeSort = switch (sortBy.toLowerCase()) {
            case "email" -> "email";
            case "firstname" -> "firstName";
            case "lastname" -> "lastName";
            default -> "createdAt";
        };

        Sort sort = direction.equalsIgnoreCase("asc") ? Sort.by(safeSort).ascending() : Sort.by(safeSort).descending();
        Page<UserResponse> users = userService.getUsers(PageRequest.of(page, size, sort));
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "Get User by ID", description = "Retrieves user profile by ID with cross-tenant access enforcement.")
    public ResponseEntity<UserResponse> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('USER_CREATE')")
    @Operation(summary = "Create User", description = "Creates a new user within the caller's tenant.")
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody CreateUserRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        UserResponse response = userService.createUser(request, ip, userAgent);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Update User Profile", description = "Updates specified profile fields of a tenant user.")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(userService.updateUser(id, request, ip, userAgent));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_DELETE')")
    @Operation(summary = "Delete User", description = "Removes a user from the caller's tenant.")
    public ResponseEntity<Void> deleteUser(
            @PathVariable UUID id,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        userService.deleteUser(id, ip, userAgent);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('ROLE_ASSIGN')")
    @Operation(summary = "Assign Roles to User", description = "Replaces or updates assigned RBAC roles for a tenant user.")
    public ResponseEntity<UserResponse> assignRoles(
            @PathVariable UUID id,
            @Valid @RequestBody AssignRolesRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientInfoResolver.getClientIp(httpRequest);
        String userAgent = clientInfoResolver.getUserAgent(httpRequest);
        return ResponseEntity.ok(userService.assignRoles(id, request, ip, userAgent));
    }
}
