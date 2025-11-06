package com.example.finalsso.entity;

import javax.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @javax.persistence.Column(unique = true)
    private String username;
    private String password;
    private String email;

    private String firstName;
    private String lastName;

    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private UserRole userRole = UserRole.END_USER; // SUPER_ADMIN, CUSTOMER_ADMIN, END_USER

    @Column(nullable = false)
    private boolean enabled = true;

    // Multi-tenant support
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = true)
    private Tenant tenant;

    // For backward compatibility: get role as String (ROLE_XXX format)
    public String getRole() {
        return "ROLE_" + userRole.name();
    }

    // For backward compatibility: set role from String
    public void setRole(String roleStr) {
        if (roleStr == null) {
            this.userRole = UserRole.END_USER;
            return;
        }
        try {
            String roleUpper = roleStr.replace("ROLE_", "").toUpperCase();
            this.userRole = UserRole.valueOf(roleUpper);
        } catch (IllegalArgumentException e) {
            // Map old role strings to new enum
            if (roleStr.equals("ROLE_ADMIN") || roleStr.equals("ADMIN")) {
                this.userRole = UserRole.SUPER_ADMIN;
            } else {
                this.userRole = UserRole.END_USER;
            }
        }
    }

    public enum UserRole {
        SUPER_ADMIN,    // Can manage all tenants and users
        CUSTOMER_ADMIN, // Can manage only their tenant's users
        END_USER        // Regular user with limited access
    }
}
