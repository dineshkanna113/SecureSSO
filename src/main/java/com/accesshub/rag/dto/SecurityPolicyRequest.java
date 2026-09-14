package com.accesshub.rag.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SecurityPolicyRequest {
    @NotBlank(message = "Title is required")
    private String title;

    @NotBlank(message = "Category is required")
    private String category;

    @NotBlank(message = "Content is required")
    private String content;

    private String tags;
}
