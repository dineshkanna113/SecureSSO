package com.example.finalsso.service;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Service to map username to company and role for routing decisions
 */
@Service
public class UserCompanyMapper {
    
    private final UserRepository userRepository;
    
    public UserCompanyMapper(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    /**
     * Get user info by username
     */
    @Transactional(readOnly = true)
    public Optional<UserInfo> getUserInfo(String username) {
        // Use JOIN FETCH to eagerly load tenant and avoid lazy initialization issues
        return userRepository.findByUsernameWithTenant(username)
            .map(user -> {
                // Tenant is already loaded via JOIN FETCH, safe to access
                String companySlug = null;
                String companyDisplayName = null;
                Long tenantId = null;
                if (user.getTenant() != null) {
                    var tenant = user.getTenant();
                    tenantId = tenant.getTenantId();
                    companyDisplayName = tenant.getTenantName();
                    companySlug = slugify(companyDisplayName);
                }
                return new UserInfo(
                    user.getUsername(),
                    user.getUserRole(),
                    companySlug,
                    companyDisplayName,
                    tenantId
                );
            });
    }
    
    /**
     * Get redirect path after username entry
     */
    @Transactional(readOnly = true)
    public String getRedirectPath(String username) {
        return getUserInfo(username)
            .map(info -> {
                if (info.role == User.UserRole.SUPER_ADMIN) {
                    return "/super-admin/dashboard";
                } else if (info.companySlug != null) {
                    if (info.role == User.UserRole.CUSTOMER_ADMIN) {
                        return "/" + info.companySlug + "/customer-admin/dashboard";
                    } else if (info.role == User.UserRole.END_USER) {
                        return "/" + info.companySlug + "/enduser/dashboard";
                    }
                }
                return "/login?error=invalid_user";
            })
            .orElse("/login?error=user_not_found");
    }
    
    /**
     * Get password page path
     */
    @Transactional(readOnly = true)
    public String getPasswordPagePath(String username) {
        return getUserInfo(username)
            .map(info -> {
                if (info.role == User.UserRole.SUPER_ADMIN) {
                    return "/super-admin/password";
                } else if (info.companySlug != null) {
                    return "/" + info.companySlug + "/password";
                }
                return "/login?error=invalid_user";
            })
            .orElse("/login?error=user_not_found");
    }
    
    /**
     * Validate company context in URL matches user's company
     */
    @Transactional(readOnly = true)
    public boolean validateCompanyContext(String username, String companyName) {
        return getUserInfo(username)
            .map(info -> {
                if (info.role == User.UserRole.SUPER_ADMIN) {
                    return true; // Super admin can access any company context
                }
                if (info.companySlug == null) {
                    return false;
                }
                String requestedSlug = slugify(companyName);
                return info.companySlug.equalsIgnoreCase(requestedSlug);
            })
            .orElse(false);
    }
    
    /**
     * Get company name for user
     */
    @Transactional(readOnly = true)
    public Optional<String> getCompanyName(String username) {
        return getUserInfo(username).map(info -> info.companySlug);
    }

    @Transactional(readOnly = true)
    public Optional<String> getCompanyDisplayName(String username) {
        return getUserInfo(username).map(info -> info.companyDisplayName != null ? info.companyDisplayName : info.companySlug);
    }

    private String slugify(String input) {
        if (input == null) {
            return null;
        }
        String slug = input.trim().toLowerCase()
            .replaceAll("[^a-z0-9]+", "-")
            .replaceAll("^-+", "")
            .replaceAll("-+$", "");
        return slug.isEmpty() ? input.trim().toLowerCase().replace(' ', '-') : slug;
    }
    
    /**
     * User information holder
     */
    public static class UserInfo {
        public final String username;
        public final User.UserRole role;
        public final String companySlug;
        public final String companyDisplayName;
        public final Long tenantId;
        
        public UserInfo(String username, User.UserRole role, String companySlug, String companyDisplayName, Long tenantId) {
            this.username = username;
            this.role = role;
            this.companySlug = companySlug;
            this.companyDisplayName = companyDisplayName;
            this.tenantId = tenantId;
        }
    }
}

