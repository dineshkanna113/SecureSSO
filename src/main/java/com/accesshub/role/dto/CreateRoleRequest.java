package com.accesshub.role.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Set;

@Data
public class CreateRoleRequest {
    @NotBlank(message = "Role name is required")
    private String name;
    private String description;
    private Set<String> permissionCodes;
}
