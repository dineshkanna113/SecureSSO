package com.accesshub.user.dto;

import lombok.Data;

@Data
public class UpdateUserRequest {
    private String firstName;
    private String lastName;
    private Boolean enabled;
    private Boolean locked;
}
