package com.example.finalsso.service;

import com.example.finalsso.entity.Tenant;
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
        return userRepository.findByUsername(username)
            .map(user -> {
                // Initialize tenant to avoid lazy loading issues
                String companyName = null;
                Long tenantId = null;
                if (user.getTenant() != null) {
                    // Force initialization
                    tenantId = user.getTenant().getTenantId();
                    companyName = user.getTenant().getTenantName();
                }
                return new UserInfo(
                    user.getUsername(),
                    user.getUserRole(),
                    companyName,
                    tenantId
                );
            });
    }
    
    /**
     * Get redirect path after username entry
     */
    public String getRedirectPath(String username) {
        return getUserInfo(username)
            .map(info -> {
                if (info.role == User.UserRole.SUPER_ADMIN) {
                    return "/super-admin/dashboard";
                } else if (info.companyName != null) {
                    if (info.role == User.UserRole.CUSTOMER_ADMIN) {
                        return "/" + info.companyName + "/customer-admin/dashboard";
                    } else if (info.role == User.UserRole.END_USER) {
                        return "/" + info.companyName + "/enduser/dashboard";
                    }
                }
                return "/login?error=invalid_user";
            })
            .orElse("/login?error=user_not_found");
    }
    
    /**
     * Get password page path
     */
    public String getPasswordPagePath(String username) {
        return getUserInfo(username)
            .map(info -> {
                if (info.role == User.UserRole.SUPER_ADMIN) {
                    return "/super-admin/password";
                } else if (info.companyName != null) {
                    return "/" + info.companyName + "/password";
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
                return info.companyName != null && info.companyName.equalsIgnoreCase(companyName);
            })
            .orElse(false);
    }
    
    /**
     * Get company name for user
     */
    public Optional<String> getCompanyName(String username) {
        return getUserInfo(username).map(info -> info.companyName);
    }
    
    /**
     * User information holder
     */
    public static class UserInfo {
        public final String username;
        public final User.UserRole role;
        public final String companyName;
        public final Long tenantId;
        
        public UserInfo(String username, User.UserRole role, String companyName, Long tenantId) {
            this.username = username;
            this.role = role;
            this.companyName = companyName;
            this.tenantId = tenantId;
        }
    }
}

