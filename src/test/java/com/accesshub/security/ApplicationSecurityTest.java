package com.accesshub.security;

import com.accesshub.application.dto.ApplicationResponse;
import com.accesshub.application.dto.CreateApplicationRequest;
import com.accesshub.application.dto.UpdateApplicationRequest;
import com.accesshub.auth.dto.LoginRequest;
import com.accesshub.auth.dto.LoginResponse;
import com.accesshub.auth.dto.RegisterTenantRequest;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class ApplicationSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Application Security: Strict redirect URI validation, secret rotation, and secret masking")
    void testApplicationManagement_SecurityControls() throws Exception {
        String slug = "appsec-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Register Tenant
        RegisterTenantRequest reg = new RegisterTenantRequest();
        reg.setTenantName("AppSec Corp");
        reg.setTenantSlug(slug);
        reg.setAdminEmail("appadmin@appsec.com");
        reg.setAdminPassword("Password123!");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(reg)))
                .andExpect(status().isCreated());

        // 2. Login
        LoginRequest login = new LoginRequest();
        login.setTenantSlug(slug);
        login.setEmail("appadmin@appsec.com");
        login.setPassword("Password123!");

        MvcResult loginRes = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse auth = objectMapper.readValue(loginRes.getResponse().getContentAsString(), LoginResponse.class);

        // 3. Reject Wildcard Redirect URI (Open redirect mitigation)
        CreateApplicationRequest wildcardApp = new CreateApplicationRequest();
        wildcardApp.setName("Wildcard App");
        wildcardApp.setRedirectUris("https://*.attacker.com/oauth/callback");

        mockMvc.perform(post("/api/applications")
                .header("Authorization", "Bearer " + auth.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(wildcardApp)))
                .andExpect(status().isBadRequest());

        // 4. Reject Insecure Plain HTTP on Non-Localhost
        CreateApplicationRequest plainHttpApp = new CreateApplicationRequest();
        plainHttpApp.setName("Insecure App");
        plainHttpApp.setRedirectUris("http://attacker.com/oauth/callback");

        mockMvc.perform(post("/api/applications")
                .header("Authorization", "Bearer " + auth.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(plainHttpApp)))
                .andExpect(status().isBadRequest());

        // 5. Valid App Registration (HTTPS & Localhost allowed)
        CreateApplicationRequest validApp = new CreateApplicationRequest();
        validApp.setName("Production Dashboard");
        validApp.setRedirectUris("https://dashboard.appsec.com/callback, http://localhost:3000/callback");
        validApp.setAllowedScopes("openid profile email");

        MvcResult createRes = mockMvc.perform(post("/api/applications")
                .header("Authorization", "Bearer " + auth.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validApp)))
                .andExpect(status().isCreated())
                .andReturn();

        ApplicationResponse createdApp = objectMapper.readValue(createRes.getResponse().getContentAsString(), ApplicationResponse.class);
        assertNotNull(createdApp.getClientId());
        assertNotNull(createdApp.getClientSecret()); // Returned exactly once upon creation!
        String initialSecret = createdApp.getClientSecret();

        // 6. Verify GET Does NOT Return Raw Client Secret (Secret Masking)
        MvcResult getRes = mockMvc.perform(get("/api/applications/" + createdApp.getId())
                .header("Authorization", "Bearer " + auth.getAccessToken()))
                .andExpect(status().isOk())
                .andReturn();

        ApplicationResponse fetchedApp = objectMapper.readValue(getRes.getResponse().getContentAsString(), ApplicationResponse.class);
        assertNull(fetchedApp.getClientSecret()); // Client secret MUST be null on subsequent reads

        // 7. Rotate Secret
        MvcResult rotateRes = mockMvc.perform(post("/api/applications/" + createdApp.getId() + "/rotate-secret")
                .header("Authorization", "Bearer " + auth.getAccessToken()))
                .andExpect(status().isOk())
                .andReturn();

        ApplicationResponse rotatedApp = objectMapper.readValue(rotateRes.getResponse().getContentAsString(), ApplicationResponse.class);
        assertNotNull(rotatedApp.getClientSecret());
        assertNotEquals(initialSecret, rotatedApp.getClientSecret());
        assertEquals(createdApp.getClientId(), rotatedApp.getClientId());

        // 8. Update Application Settings
        UpdateApplicationRequest updateReq = new UpdateApplicationRequest();
        updateReq.setName("Updated Dashboard");
        updateReq.setRedirectUris("https://newdashboard.appsec.com/callback");
        updateReq.setAllowedScopes("openid profile");

        mockMvc.perform(put("/api/applications/" + createdApp.getId())
                .header("Authorization", "Bearer " + auth.getAccessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk());
    }
}
