package com.accesshub.application.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreateApplicationRequest {

    @NotBlank(message = "Application name is required")
    private String name;

    private String redirectUris;
    private String allowedScopes;
}
