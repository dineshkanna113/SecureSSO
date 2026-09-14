package com.accesshub.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "AccessHub — Enterprise Multi-Tenant Identity & Access Management (IAM) Platform API",
        version = "1.0.0",
        description = "Production-grade multi-tenant IAM system featuring tenant data isolation, JWT authentication with refresh token rotation, Redis-based token revocation and rate limiting, fine-grained RBAC, OAuth client management, async security audit logging, and tenant-isolated AI RAG LLM Security Assistant.",
        contact = @Contact(name = "AccessHub Engineering", email = "admin@accesshub.io"),
        license = @License(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0")
    ),
    servers = {
        @Server(url = "http://localhost:8080", description = "Local Development Server")
    }
)
@SecurityScheme(
    name = "Bearer Authentication",
    type = SecuritySchemeType.HTTP,
    bearerFormat = "JWT",
    scheme = "bearer",
    description = "Enter JWT access token issued by POST /api/auth/login"
)
public class OpenApiConfig {
}
