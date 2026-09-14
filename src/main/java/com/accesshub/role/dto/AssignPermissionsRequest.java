package com.accesshub.role.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class AssignPermissionsRequest {
    @NotEmpty(message = "Permission codes set must not be empty")
    private Set<String> permissionCodes;
}
