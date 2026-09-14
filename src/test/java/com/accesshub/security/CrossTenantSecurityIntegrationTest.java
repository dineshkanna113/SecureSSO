package com.accesshub.security;

import com.accesshub.auth.dto.*;
import com.accesshub.role.dto.AssignPermissionsRequest;
import com.accesshub.role.dto.CreateRoleRequest;
import com.accesshub.user.dto.AssignRolesRequest;
import com.accesshub.user.dto.CreateUserRequest;
import com.accesshub.user.dto.UpdateUserRequest;
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

import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class CrossTenantSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Cross-Tenant Isolation: Complete read, update, delete, and role assignment isolation across tenants")
    void testCrossTenantIsolation_Comprehensive() throws Exception {
        // 1. Register Tenant A
        RegisterTenantRequest reqA = new RegisterTenantRequest();
        reqA.setTenantName("Tenant Alpha");
        reqA.setTenantSlug("alpha-" + UUID.randomUUID().toString().substring(0, 8));
        reqA.setAdminEmail("admin@alpha.com");
        reqA.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reqA)))
                .andExpect(status().isCreated());

        // 2. Login Tenant A -> Get JWT A
        LoginRequest loginA = new LoginRequest();
        loginA.setTenantSlug(reqA.getTenantSlug());
        loginA.setEmail("admin@alpha.com");
        loginA.setPassword("Password123!");

        MvcResult loginResA = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginA)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse tokenA = objectMapper.readValue(loginResA.getResponse().getContentAsString(), LoginResponse.class);

        // 3. Register Tenant B
        RegisterTenantRequest reqB = new RegisterTenantRequest();
        reqB.setTenantName("Tenant Beta");
        reqB.setTenantSlug("beta-" + UUID.randomUUID().toString().substring(0, 8));
        reqB.setAdminEmail("admin@beta.com");
        reqB.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reqB)))
                .andExpect(status().isCreated());

        // 4. Login Tenant B -> Get JWT B
        LoginRequest loginB = new LoginRequest();
        loginB.setTenantSlug(reqB.getTenantSlug());
        loginB.setEmail("admin@beta.com");
        loginB.setPassword("Password123!");

        MvcResult loginResB = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginB)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse tokenB = objectMapper.readValue(loginResB.getResponse().getContentAsString(), LoginResponse.class);

        // 5. Tenant A creates a user in Tenant A
        CreateUserRequest userReq = new CreateUserRequest();
        userReq.setEmail("user1@alpha.com");
        userReq.setPassword("Password123!");
        userReq.setFirstName("User");
        userReq.setLastName("Alpha");

        MvcResult userRes = mockMvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + tokenA.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userReq)))
                .andExpect(status().isCreated())
                .andReturn();

        String userContent = userRes.getResponse().getContentAsString();
        UUID tenantAUserId = UUID.fromString(objectMapper.readTree(userContent).get("id").asText());

        // 6. Cross-Tenant READ: Tenant B tries to read Tenant A's user -> 404 NOT FOUND
        mockMvc.perform(get("/api/users/" + tenantAUserId)
                .header("Authorization", "Bearer " + tokenB.getAccessToken()))
                .andExpect(status().isNotFound());

        // 7. Cross-Tenant UPDATE: Tenant B tries to update Tenant A's user -> 404 NOT FOUND
        UpdateUserRequest updateReq = new UpdateUserRequest();
        updateReq.setFirstName("HackedName");
        mockMvc.perform(patch("/api/users/" + tenantAUserId)
                .header("Authorization", "Bearer " + tokenB.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isNotFound());

        // 8. Cross-Tenant ROLE ASSIGNMENT: Tenant B tries to assign roles to Tenant A's user -> 404 NOT FOUND
        AssignRolesRequest assignReq = new AssignRolesRequest();
        assignReq.setRoleNames(Set.of("USER"));
        mockMvc.perform(post("/api/users/" + tenantAUserId + "/roles")
                .header("Authorization", "Bearer " + tokenB.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(assignReq)))
                .andExpect(status().isNotFound());

        // 9. Cross-Tenant DELETE: Tenant B tries to delete Tenant A's user -> 404 NOT FOUND
        mockMvc.perform(delete("/api/users/" + tenantAUserId)
                .header("Authorization", "Bearer " + tokenB.getAccessToken()))
                .andExpect(status().isNotFound());

        // 10. Multi-Tenant Email Namespace: Same email address in Tenant B succeeds
        CreateUserRequest userReqInB = new CreateUserRequest();
        userReqInB.setEmail("user1@alpha.com"); // identical email but in Tenant B
        userReqInB.setPassword("Password123!");
        userReqInB.setFirstName("User");
        userReqInB.setLastName("Beta");

        mockMvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + tokenB.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userReqInB)))
                .andExpect(status().isCreated());

        // 11. Duplicate email inside the SAME tenant fails
        mockMvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + tokenB.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userReqInB)))
                .andExpect(status().isBadRequest());
    }
}
