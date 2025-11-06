package com.example.finalsso.controller;

import com.example.finalsso.entity.Tenant;
import com.example.finalsso.entity.User;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/super-admin")
public class SuperAdminController {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SuperAdminController.class);

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public SuperAdminController(UserRepository userRepository, 
                                TenantRepository tenantRepository,
                                UserService userService,
                                PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/dashboard")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String dashboard(Model model, org.springframework.security.core.Authentication authentication) {
        try {
            log.info("SuperAdminController: Loading dashboard...");
            
            // Check authentication
            if (authentication == null || !authentication.isAuthenticated()) {
                log.warn("SuperAdminController: User not authenticated");
                return "redirect:/login?error=not_authenticated";
            }
            
            log.info("SuperAdminController: Authenticated user: {}", authentication.getName());
            log.info("SuperAdminController: Authorities: {}", authentication.getAuthorities());
            
            // Get all tenants
            List<Tenant> tenants = tenantRepository.findAll();
            if (tenants == null) {
                tenants = new java.util.ArrayList<>();
            }
            log.info("SuperAdminController: Found {} tenants", tenants.size());
            
            // Get all users (super admin can see all)
            List<User> users = userRepository.findAll();
            if (users == null) {
                users = new java.util.ArrayList<>();
            }
            
            // Initialize tenant relationships to avoid lazy loading issues
            users.forEach(u -> {
                if (u.getTenant() != null) {
                    u.getTenant().getTenantId(); // Force initialization
                }
            });
            
            log.info("SuperAdminController: Found {} users", users.size());
            
            model.addAttribute("tenants", tenants);
            model.addAttribute("users", users);
            model.addAttribute("totalTenants", tenants.size());
            model.addAttribute("totalUsers", users.size());
            
            log.info("SuperAdminController: Returning template 'superadmin/dashboard'");
            return "superadmin/dashboard";
        } catch (Exception e) {
            log.error("SuperAdminController ERROR: ", e);
            model.addAttribute("error", "Error loading dashboard: " + e.getMessage());
            model.addAttribute("tenants", new java.util.ArrayList<>());
            model.addAttribute("users", new java.util.ArrayList<>());
            model.addAttribute("totalTenants", 0);
            model.addAttribute("totalUsers", 0);
            return "superadmin/dashboard";
        }
    }

    @GetMapping("/test")
    public String test(org.springframework.security.core.Authentication authentication, Model model) {
        if (authentication == null) {
            model.addAttribute("message", "Not authenticated");
            return "error";
        }
        model.addAttribute("username", authentication.getName());
        model.addAttribute("authorities", authentication.getAuthorities());
        model.addAttribute("authenticated", authentication.isAuthenticated());
        return "superadmin/test";
    }

    // ========== Tenant Management ==========
    
    @GetMapping("/tenants/new")
    public String newTenant(Model model) {
        model.addAttribute("tenant", new Tenant());
        return "superadmin/tenant_form";
    }

    @PostMapping("/tenants")
    public String createTenant(@ModelAttribute Tenant tenant, 
                               @RequestParam(required = false) String tenantName,
                               @RequestParam(required = false) String adminUsername,
                               @RequestParam(required = false) String adminEmail,
                               @RequestParam(required = false) String adminFirstName,
                               @RequestParam(required = false) String adminLastName,
                               @RequestParam(required = false) String adminPassword,
                               Model model, RedirectAttributes ra) {
        try {
            String name = tenantName != null ? tenantName.trim() : (tenant.getTenantName() != null ? tenant.getTenantName().trim() : "");
            if (name.isEmpty()) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Tenant name is required");
                return "superadmin/tenant_form";
            }
            
            if (tenantRepository.existsByTenantName(name)) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Tenant name already exists");
                return "superadmin/tenant_form";
            }
            
            // Validate customer-admin fields
            if (adminUsername == null || adminUsername.trim().isEmpty()) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin username is required");
                return "superadmin/tenant_form";
            }
            
            String adminUsernameLower = adminUsername.trim().toLowerCase();
            if (adminUsernameLower.length() < 4) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin username must be at least 4 characters long");
                return "superadmin/tenant_form";
            }
            
            if (!adminUsernameLower.matches("^[a-z0-9_]+$")) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin username must be lowercase and contain only letters, numbers, and underscores");
                return "superadmin/tenant_form";
            }
            
            if (userRepository.findByUsername(adminUsernameLower).isPresent()) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin username already exists");
                return "superadmin/tenant_form";
            }
            
            if (adminEmail == null || adminEmail.trim().isEmpty()) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin email is required");
                return "superadmin/tenant_form";
            }
            
            if (adminPassword == null || adminPassword.isEmpty()) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin password is required");
                return "superadmin/tenant_form";
            }
            
            if (adminPassword.length() < 6 || adminPassword.length() > 10) {
                model.addAttribute("tenant", tenant);
                model.addAttribute("error", "Admin password must be between 6 and 10 characters");
                return "superadmin/tenant_form";
            }
            
            // Create tenant first
            Tenant newTenant = new Tenant();
            newTenant.setTenantName(name);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String createdBy = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName()) 
                ? auth.getName() : "system";
            newTenant.setCreatedBy(createdBy);
            newTenant.setActive(true);
            tenantRepository.save(newTenant);
            
            // Create customer-admin user with provided details
            User adminUser = new User();
            adminUser.setUsername(adminUsernameLower);
            adminUser.setPassword(passwordEncoder.encode(adminPassword));
            adminUser.setEmail(adminEmail.trim());
            adminUser.setFirstName(adminFirstName != null ? adminFirstName.trim() : "Admin");
            adminUser.setLastName(adminLastName != null ? adminLastName.trim() : name);
            adminUser.setUserRole(User.UserRole.CUSTOMER_ADMIN);
            adminUser.setEnabled(true);
            adminUser.setTenant(newTenant);
            userRepository.save(adminUser);
            
            ra.addFlashAttribute("success", "Tenant and customer-admin created successfully. Admin username: " + adminUsernameLower);
            return "redirect:/super-admin/dashboard";
        } catch (Exception e) {
            model.addAttribute("tenant", tenant);
            model.addAttribute("error", "Error creating tenant: " + e.getMessage());
            return "superadmin/tenant_form";
        }
    }

    @GetMapping("/tenants/{id}/edit")
    public String editTenant(@PathVariable Long id, Model model) {
        Optional<Tenant> tenant = tenantRepository.findById(id);
        if (tenant.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=tenant_not_found";
        }
        model.addAttribute("tenant", tenant.get());
        return "superadmin/tenant_form";
    }

    @PostMapping("/tenants/{id}")
    public String updateTenant(@PathVariable Long id, 
                               @RequestParam String tenantName,
                               @RequestParam(required = false) Boolean active,
                               Model model, RedirectAttributes ra) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(id);
        if (tenantOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=tenant_not_found";
        }
        
        Tenant tenant = tenantOpt.get();
        String name = tenantName.trim();
        
        if (name.isEmpty()) {
            model.addAttribute("tenant", tenant);
            model.addAttribute("error", "Tenant name is required");
            return "superadmin/tenant_form";
        }
        
        // Check for duplicate name (excluding current tenant)
        Optional<Tenant> existing = tenantRepository.findByTenantName(name);
        if (existing.isPresent() && !existing.get().getTenantId().equals(id)) {
            model.addAttribute("tenant", tenant);
            model.addAttribute("error", "Tenant name already exists");
            return "superadmin/tenant_form";
        }
        
        tenant.setTenantName(name);
        if (active != null) {
            tenant.setActive(active);
        }
        tenantRepository.save(tenant);
        
        ra.addFlashAttribute("success", "Tenant updated successfully");
        return "redirect:/super-admin/dashboard";
    }

    @PostMapping("/tenants/{id}/delete")
    public String deleteTenant(@PathVariable Long id, RedirectAttributes ra) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(id);
        if (tenantOpt.isPresent()) {
            // Check if tenant has users
            List<User> tenantUsers = userRepository.findByTenant_TenantId(id);
            if (!tenantUsers.isEmpty()) {
                ra.addFlashAttribute("error", "Cannot delete tenant with assigned users. Please remove users first.");
                return "redirect:/super-admin/dashboard";
            }
            tenantRepository.deleteById(id);
            ra.addFlashAttribute("success", "Tenant deleted successfully");
        }
        return "redirect:/super-admin/dashboard";
    }

    // ========== Tenant User Management ==========
    
    @GetMapping("/tenants/{tenantId}/users")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String viewTenantUsers(@PathVariable Long tenantId, Model model) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        if (tenantOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=tenant_not_found";
        }
        
        Tenant tenant = tenantOpt.get();
        List<User> users = userRepository.findByTenant_TenantId(tenantId);
        
        // Initialize tenant relationships to avoid lazy loading issues
        users.forEach(u -> {
            if (u.getTenant() != null) {
                u.getTenant().getTenantName(); // Force initialization
            }
        });
        
        model.addAttribute("tenant", tenant);
        model.addAttribute("users", users);
        return "superadmin/tenant_users";
    }

    @GetMapping("/tenants/{tenantId}/users/new")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String newTenantUser(@PathVariable Long tenantId, Model model) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        if (tenantOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=tenant_not_found";
        }
        
        User user = new User();
        model.addAttribute("user", user);
        model.addAttribute("tenant", tenantOpt.get());
        model.addAttribute("tenantId", tenantId);
        return "superadmin/tenant_user_form";
    }

    @PostMapping("/tenants/{tenantId}/users")
    @org.springframework.transaction.annotation.Transactional
    public String createTenantUser(@PathVariable Long tenantId,
                                   @ModelAttribute User user,
                                   @RequestParam(required = false) String userRole,
                                   @RequestParam(required = false) String enabled,
                                   @RequestParam(required = false) String password,
                                   Model model) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        if (tenantOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=tenant_not_found";
        }
        
        Tenant tenant = tenantOpt.get();
        
        // Validate username
        String username = user.getUsername();
        if (username == null || username.length() < 4) {
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username must be at least 4 characters long");
            return "superadmin/tenant_user_form";
        }
        
        String usernameLower = username.toLowerCase();
        if (!username.equals(usernameLower) || !usernameLower.matches("^[a-z0-9_]+$")) {
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username must be lowercase and contain only letters, numbers, and underscores");
            return "superadmin/tenant_user_form";
        }
        user.setUsername(usernameLower);
        
        // Check for duplicate username
        if (userRepository.findByUsername(usernameLower).isPresent()) {
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username already exists");
            return "superadmin/tenant_user_form";
        }
        
        // Set role
        if (userRole != null && !userRole.isEmpty()) {
            user.setRole(userRole);
        } else {
            user.setRole("ROLE_END_USER");
        }
        
        // Validate password (from request parameter)
        if (password == null || password.isEmpty()) {
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Password is required");
            return "superadmin/tenant_user_form";
        }
        if (password.length() < 6 || password.length() > 10) {
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Password must be between 6 and 10 characters");
            return "superadmin/tenant_user_form";
        }
        user.setPassword(passwordEncoder.encode(password));
        
        // Set enabled status
        if (enabled != null) {
            user.setEnabled("true".equalsIgnoreCase(enabled));
        } else {
            user.setEnabled(true); // Default to enabled
        }
        
        // Assign tenant (cannot be SUPER_ADMIN for tenant users)
        if (user.getUserRole() == User.UserRole.SUPER_ADMIN) {
            user.setUserRole(User.UserRole.CUSTOMER_ADMIN); // Default to CUSTOMER_ADMIN for tenant users
        }
        user.setTenant(tenant);
        
        try {
            // Ensure user has all required fields
            if (user.getUserRole() == null) {
                user.setUserRole(User.UserRole.END_USER);
            }
            userRepository.saveAndFlush(user);
            return "redirect:/super-admin/tenants/" + tenantId + "/users?success=user_created";
        } catch (Exception e) {
            log.error("Error creating user: ", e);
            model.addAttribute("user", user);
            model.addAttribute("tenant", tenant);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Error creating user: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
            return "superadmin/tenant_user_form";
        }
    }

    @GetMapping("/tenants/{tenantId}/users/{userId}/edit")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String editTenantUser(@PathVariable Long tenantId, @PathVariable Long userId, Model model) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        Optional<User> userOpt = userRepository.findById(userId);
        
        if (tenantOpt.isEmpty() || userOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=not_found";
        }
        
        User user = userOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (user.getTenant() != null) {
            user.getTenant().getTenantId(); // Force initialization
            if (!user.getTenant().getTenantId().equals(tenantId)) {
                return "redirect:/super-admin/tenants/" + tenantId + "/users?error=user_not_in_tenant";
            }
        } else {
            return "redirect:/super-admin/tenants/" + tenantId + "/users?error=user_not_in_tenant";
        }
        
        model.addAttribute("user", user);
        model.addAttribute("tenant", tenantOpt.get());
        model.addAttribute("tenantId", tenantId);
        return "superadmin/tenant_user_form";
    }

    @PostMapping("/tenants/{tenantId}/users/{userId}")
    @org.springframework.transaction.annotation.Transactional
    public String updateTenantUser(@PathVariable Long tenantId, @PathVariable Long userId,
                                   @ModelAttribute User user,
                                   @RequestParam(required = false) String userRole,
                                   @RequestParam(required = false) String enabled,
                                   @RequestParam(required = false) String password,
                                   Model model) {
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        Optional<User> existingOpt = userRepository.findById(userId);
        
        if (tenantOpt.isEmpty() || existingOpt.isEmpty()) {
            return "redirect:/super-admin/dashboard?error=not_found";
        }
        
        User existing = existingOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (existing.getTenant() != null) {
            existing.getTenant().getTenantId(); // Force initialization
            if (!existing.getTenant().getTenantId().equals(tenantId)) {
                return "redirect:/super-admin/tenants/" + tenantId + "/users?error=user_not_in_tenant";
            }
        } else {
            return "redirect:/super-admin/tenants/" + tenantId + "/users?error=user_not_in_tenant";
        }
        
        // Validate username
        String username = user.getUsername();
        if (username == null || username.length() < 4) {
            model.addAttribute("user", existing);
            model.addAttribute("tenant", tenantOpt.get());
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username must be at least 4 characters long");
            return "superadmin/tenant_user_form";
        }
        
        String usernameLower = username.toLowerCase();
        if (!username.equals(usernameLower) || !usernameLower.matches("^[a-z0-9_]+$")) {
            model.addAttribute("user", existing);
            model.addAttribute("tenant", tenantOpt.get());
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username must be lowercase and contain only letters, numbers, and underscores");
            return "superadmin/tenant_user_form";
        }
        
        // Check for duplicate username
        Optional<User> clash = userRepository.findByUsername(usernameLower);
        if (clash.isPresent() && !clash.get().getId().equals(userId)) {
            model.addAttribute("user", existing);
            model.addAttribute("tenant", tenantOpt.get());
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Username already exists");
            return "superadmin/tenant_user_form";
        }
        
        existing.setUsername(usernameLower);
        if (user.getEmail() != null) {
            existing.setEmail(user.getEmail());
        }
        if (user.getFirstName() != null) {
            existing.setFirstName(user.getFirstName());
        }
        if (user.getLastName() != null) {
            existing.setLastName(user.getLastName());
        }
        // Enabled field from form parameter
        if (enabled != null) {
            existing.setEnabled("true".equalsIgnoreCase(enabled));
        }
        
        // Update role
        if (userRole != null && !userRole.isEmpty()) {
            existing.setRole(userRole);
            // Ensure tenant users cannot be SUPER_ADMIN
            if (existing.getUserRole() == User.UserRole.SUPER_ADMIN) {
                existing.setUserRole(User.UserRole.CUSTOMER_ADMIN);
            }
        }
        
        // Update password if provided (from request parameter)
        if (password != null && !password.isEmpty() && !password.trim().isEmpty()) {
            if (password.length() < 6 || password.length() > 10) {
                model.addAttribute("user", existing);
                model.addAttribute("tenant", tenantOpt.get());
                model.addAttribute("tenantId", tenantId);
                model.addAttribute("error", "Password must be between 6 and 10 characters");
                return "superadmin/tenant_user_form";
            }
            existing.setPassword(passwordEncoder.encode(password));
        }
        
        // Ensure tenant is still assigned
        existing.setTenant(tenantOpt.get());
        
        // Ensure userRole is set
        if (existing.getUserRole() == null) {
            existing.setUserRole(User.UserRole.END_USER);
        }
        
        try {
            userRepository.saveAndFlush(existing);
            return "redirect:/super-admin/tenants/" + tenantId + "/users?success=user_updated";
        } catch (Exception e) {
            log.error("Error updating user: ", e);
            model.addAttribute("user", existing);
            model.addAttribute("tenant", tenantOpt.get());
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("error", "Error updating user: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
            return "superadmin/tenant_user_form";
        }
    }

    @PostMapping("/tenants/{tenantId}/users/{userId}/delete")
    @org.springframework.transaction.annotation.Transactional
    public String deleteTenantUser(@PathVariable Long tenantId, @PathVariable Long userId, RedirectAttributes ra) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Initialize tenant to avoid lazy loading issues
            if (user.getTenant() != null) {
                user.getTenant().getTenantId(); // Force initialization
                if (user.getTenant().getTenantId().equals(tenantId)) {
                    userRepository.deleteById(userId);
                    ra.addFlashAttribute("success", "User deleted successfully");
                } else {
                    ra.addFlashAttribute("error", "User does not belong to this tenant");
                }
            } else {
                ra.addFlashAttribute("error", "User does not belong to this tenant");
            }
        }
        return "redirect:/super-admin/tenants/" + tenantId + "/users";
    }
}

