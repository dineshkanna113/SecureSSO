package com.example.finalsso.service;

import com.example.finalsso.entity.Tenant;
import com.example.finalsso.entity.User;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TenantRepository tenantRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Register a new user (END_USER only - registration is open for end users)
     * Maps user to tenant based on company name
     */
    public User register(User user, String companyName) {
        // Validate username: lowercase only, min 4 chars, alphanumeric + underscore
        String username = user.getUsername();
        if (username == null || username.length() < 4) {
            throw new IllegalArgumentException("Username must be at least 4 characters long.");
        }
        String usernameLower = username.toLowerCase();
        if (!username.equals(usernameLower) || !usernameLower.matches("^[a-z0-9_]+$")) {
            throw new IllegalArgumentException("Username must be lowercase and contain only letters, numbers, and underscores.");
        }
        user.setUsername(usernameLower);
        
        // Validate password: 6-10 characters
        String password = user.getPassword();
        if (password == null || password.length() < 6 || password.length() > 10) {
            throw new IllegalArgumentException("Password must be between 6 and 10 characters.");
        }
        
        // Registration is only for END_USER role
        user.setUserRole(User.UserRole.END_USER);
        
        // Map user to tenant based on company name
        if (companyName != null && !companyName.trim().isEmpty()) {
            Tenant tenant = findOrCreateTenant(companyName.trim());
            user.setTenant(tenant);
        }
        
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * Find existing tenant by name, or create new one if doesn't exist
     * During registration, there's no authenticated user, so use "system" as createdBy
     */
    private Tenant findOrCreateTenant(String companyName) {
        return tenantRepository.findByTenantName(companyName)
            .orElseGet(() -> {
                Tenant newTenant = new Tenant();
                newTenant.setTenantName(companyName);
                // Get current user (Super Admin) who is creating the tenant, or "system" for registration
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                String createdBy = "system";
                if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                    createdBy = auth.getName();
                }
                newTenant.setCreatedBy(createdBy);
                newTenant.setActive(true);
                return tenantRepository.save(newTenant);
            });
    }

    /**
     * Get all users accessible by current user (tenant-aware)
     */
    public List<User> getAccessibleUsers() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return List.of();
        }
        
        String username = auth.getName();
        User currentUser = userRepository.findByUsername(username)
            .orElse(null);
        
        if (currentUser == null) {
            return List.of();
        }
        
        // SUPER_ADMIN: can see all users
        if (currentUser.getUserRole() == User.UserRole.SUPER_ADMIN) {
            return userRepository.findAll();
        }
        
        // CUSTOMER_ADMIN: can see only users from their tenant
        if (currentUser.getUserRole() == User.UserRole.CUSTOMER_ADMIN) {
            if (currentUser.getTenant() != null) {
                return userRepository.findByTenant_TenantId(currentUser.getTenant().getTenantId());
            }
            return List.of();
        }
        
        // END_USER: can only see themselves
        return List.of(currentUser);
    }

    /**
     * Check if current user can access/modify a specific user
     */
    public boolean canAccessUser(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return false;
        }
        
        String username = auth.getName();
        User currentUser = userRepository.findByUsername(username).orElse(null);
        if (currentUser == null) {
            return false;
        }
        
        // SUPER_ADMIN can access any user
        if (currentUser.getUserRole() == User.UserRole.SUPER_ADMIN) {
            return true;
        }
        
        // Get target user
        User targetUser = userRepository.findById(userId).orElse(null);
        if (targetUser == null) {
            return false;
        }
        
        // CUSTOMER_ADMIN can access users from their tenant
        if (currentUser.getUserRole() == User.UserRole.CUSTOMER_ADMIN) {
            if (currentUser.getTenant() != null && targetUser.getTenant() != null) {
                return currentUser.getTenant().getTenantId().equals(targetUser.getTenant().getTenantId());
            }
        }
        
        // END_USER can only access themselves
        return currentUser.getId().equals(userId);
    }
}
