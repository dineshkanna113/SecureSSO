package com.accesshub.user.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class AssignRolesRequest {
    @NotEmpty(message = "At least one role name must be provided")
    private Set<String> roleNames;
}
