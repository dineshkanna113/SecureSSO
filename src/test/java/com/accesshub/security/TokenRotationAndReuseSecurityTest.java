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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class TokenRotationAndReuseSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Token Family Lifecycle: Single-use rotation, reuse detection, and family-wide revocation")
    void testRefreshTokenRotation_And_ReuseDetection() throws Exception {
        String slug = "rot-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Register Tenant
        RegisterTenantRequest reg = new RegisterTenantRequest();
        reg.setTenantName("Rotation Corp");
        reg.setTenantSlug(slug);
        reg.setAdminEmail("rotadmin@rotation.com");
        reg.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reg)))
                .andExpect(status().isCreated());

        // 2. Initial Login -> Get Token Pair 1
        LoginRequest loginReq = new LoginRequest();
        loginReq.setTenantSlug(slug);
        loginReq.setEmail("rotadmin@rotation.com");
        loginReq.setPassword("Password123!");

        MvcResult loginRes = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse pair1 = objectMapper.readValue(loginRes.getResponse().getContentAsString(), LoginResponse.class);
        String refreshToken1 = pair1.getRefreshToken();
        assertNotNull(refreshToken1);

        // 3. First Token Rotation: Exchange RefreshToken 1 for RefreshToken 2 -> SUCCESS
        RefreshTokenRequest refreshReq1 = new RefreshTokenRequest();
        refreshReq1.setRefreshToken(refreshToken1);

        MvcResult refreshRes1 = mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshReq1)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse pair2 = objectMapper.readValue(refreshRes1.getResponse().getContentAsString(), LoginResponse.class);
        String refreshToken2 = pair2.getRefreshToken();
        assertNotNull(refreshToken2);
        assertNotEquals(refreshToken1, refreshToken2);

        // 4. Second Token Rotation: Exchange RefreshToken 2 for RefreshToken 3 -> SUCCESS
        RefreshTokenRequest refreshReq2 = new RefreshTokenRequest();
        refreshReq2.setRefreshToken(refreshToken2);

        MvcResult refreshRes2 = mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshReq2)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse pair3 = objectMapper.readValue(refreshRes2.getResponse().getContentAsString(), LoginResponse.class);
        String refreshToken3 = pair3.getRefreshToken();
        assertNotNull(refreshToken3);
        assertNotEquals(refreshToken2, refreshToken3);

        // 5. ATTACK SIMULATION (REUSE DETECTION): Attacker presents already-rotated RefreshToken 1!
        // System MUST detect reuse, revoke the entire token family, and return 401 Unauthorized!
        RefreshTokenRequest maliciousReq = new RefreshTokenRequest();
        maliciousReq.setRefreshToken(refreshToken1);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(maliciousReq)))
                .andExpect(status().isUnauthorized());

        // 6. VERIFY FAMILY REVOCATION: Legitimate user's latest token (RefreshToken 3) must now be INVALID
        // because the whole family was revoked upon reuse detection!
        RefreshTokenRequest legitimateSubsequentReq = new RefreshTokenRequest();
        legitimateSubsequentReq.setRefreshToken(refreshToken3);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(legitimateSubsequentReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Session Management: Logout revokes session; Logout-all terminates all active user sessions")
    void testSessionLogout_And_LogoutAll() throws Exception {
        String slug = "sess-" + UUID.randomUUID().toString().substring(0, 8);

        RegisterTenantRequest reg = new RegisterTenantRequest();
        reg.setTenantName("Session Corp");
        reg.setTenantSlug(slug);
        reg.setAdminEmail("sessadmin@session.com");
        reg.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reg)))
                .andExpect(status().isCreated());

        // Login Session 1
        LoginRequest login = new LoginRequest();
        login.setTenantSlug(slug);
        login.setEmail("sessadmin@session.com");
        login.setPassword("Password123!");

        MvcResult res1 = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse session1 = objectMapper.readValue(res1.getResponse().getContentAsString(), LoginResponse.class);

        // Single Logout
        LogoutRequest logoutReq = new LogoutRequest();
        logoutReq.setRefreshToken(session1.getRefreshToken());

        mockMvc.perform(post("/api/auth/logout")
                .header("Authorization", "Bearer " + session1.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(logoutReq)))
                .andExpect(status().isNoContent());

        // Attempting to refresh using logged-out token fails
        RefreshTokenRequest refReq = new RefreshTokenRequest();
        refReq.setRefreshToken(session1.getRefreshToken());

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refReq)))
                .andExpect(status().isUnauthorized());

        // Login new session and perform Logout-all
        MvcResult res2 = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse session2 = objectMapper.readValue(res2.getResponse().getContentAsString(), LoginResponse.class);

        mockMvc.perform(post("/api/auth/logout-all")
                .header("Authorization", "Bearer " + session2.getAccessToken()))
                .andExpect(status().isNoContent());

        // Attempt to refresh session2 refresh token fails after logout-all
        RefreshTokenRequest refReq2 = new RefreshTokenRequest();
        refReq2.setRefreshToken(session2.getRefreshToken());

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refReq2)))
                .andExpect(status().isUnauthorized());
    }
}
