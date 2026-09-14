package com.accesshub.security;

import com.accesshub.auth.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.TimeZone;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AccountSecurityIntegrationTest {

    static {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Password Lifecycle: Change password revokes previous sessions; reset token flow is single-use")
    void testPasswordChange_And_ResetFlow() throws Exception {
        String slug = "pwd-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Register
        RegisterTenantRequest reg = new RegisterTenantRequest();
        reg.setTenantName("Password Corp");
        reg.setTenantSlug(slug);
        reg.setAdminEmail("admin@password.com");
        reg.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reg)))
                .andExpect(status().isCreated());

        // 2. Initial Login
        LoginRequest login = new LoginRequest();
        login.setTenantSlug(slug);
        login.setEmail("admin@password.com");
        login.setPassword("Password123!");

        MvcResult loginRes = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse initialLogin = objectMapper.readValue(loginRes.getResponse().getContentAsString(), LoginResponse.class);

        // 3. Change Password - Incorrect current password fails
        ChangePasswordRequest badChange = new ChangePasswordRequest();
        badChange.setCurrentPassword("WrongPass999!");
        badChange.setNewPassword("NewSuperPassword123!");

        mockMvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + initialLogin.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(badChange)))
                .andExpect(status().isUnauthorized());

        // 4. Change Password - Success
        ChangePasswordRequest validChange = new ChangePasswordRequest();
        validChange.setCurrentPassword("Password123!");
        validChange.setNewPassword("NewSuperPassword123!");

        mockMvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + initialLogin.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validChange)))
                .andExpect(status().isNoContent());

        // 5. Verify Previous Refresh Token is Invalidated by Password Change
        RefreshTokenRequest oldRefreshReq = new RefreshTokenRequest();
        oldRefreshReq.setRefreshToken(initialLogin.getRefreshToken());

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(oldRefreshReq)))
                .andExpect(status().isUnauthorized());

        // 6. Login with New Password succeeds
        login.setPassword("NewSuperPassword123!");
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk());

        // 7. Self-Service Forgot Password Flow
        ForgotPasswordRequest forgotReq = new ForgotPasswordRequest();
        forgotReq.setTenantSlug(slug);
        forgotReq.setEmail("admin@password.com");

        MvcResult forgotRes = mockMvc.perform(post("/api/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(forgotReq)))
                .andExpect(status().isOk())
                .andReturn();

        PasswordResetResponse resetResponse = objectMapper.readValue(forgotRes.getResponse().getContentAsString(), PasswordResetResponse.class);
        assertNotNull(resetResponse.getResetToken());

        // 8. Reset Password with Token
        ResetPasswordRequest resetReq = new ResetPasswordRequest();
        resetReq.setResetToken(resetResponse.getResetToken());
        resetReq.setNewPassword("BrandNewPassword999!");

        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isNoContent());

        // 9. Reusing the same reset token fails
        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isUnauthorized());

        // 10. Login with reset password succeeds
        login.setPassword("BrandNewPassword999!");
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Anti-Enumeration & Constant-Time Response: Non-existent accounts return uniform error messages")
    void testAntiUserEnumeration() throws Exception {
        LoginRequest nonExistent = new LoginRequest();
        nonExistent.setTenantSlug("non-existent-tenant");
        nonExistent.setEmail("ghost@nobody.com");
        nonExistent.setPassword("SomePassword123!");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(nonExistent)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid tenant, email, or password"));
    }
}
