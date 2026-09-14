package com.accesshub.application.dto;

import com.accesshub.application.Application;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateApplicationStatusRequest {
    @NotNull(message = "Status is required")
    private Application.ApplicationStatus status;
}
