package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.service.UserCompanyMapper;
import com.example.finalsso.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/{company}/customer-admin")
public class CompanyAdminController {

    private static final Logger log = LoggerFactory.getLogger(CompanyAdminController.class);
    
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final SSOConfigService ssoConfigService;
    private final UserService userService;
    private final UserCompanyMapper userCompanyMapper;
    private final PasswordEncoder passwordEncoder;

    public CompanyAdminController(UserRepository userRepository,
                                   TenantRepository tenantRepository,
                                   SSOConfigService ssoConfigService,
                                   UserService userService,
                                   UserCompanyMapper userCompanyMapper,
                                   PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.ssoConfigService = ssoConfigService;
        this.userService = userService;
        this.userCompanyMapper = userCompanyMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/dashboard")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String dashboard(@PathVariable String company, Model model) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = auth != null ? auth.getName() : null;
            
            if (username == null) {
                return "redirect:/login?error=not_authenticated";
            }
            
            if (!userCompanyMapper.validateCompanyContext(username, company)) {
                return "redirect:/login?error=access_denied";
            }
            
            // Get current user's tenant
            Optional<User> currentUserOpt = userRepository.findByUsername(username);
            if (currentUserOpt.isEmpty()) {
                return "redirect:/login?error=user_not_found";
            }
            
            var currentUser = currentUserOpt.get();
            if (currentUser.getTenant() == null) {
                return "redirect:/login?error=no_tenant_assigned";
            }
            
            // Initialize tenant to avoid lazy loading issues
            currentUser.getTenant().getTenantId(); // Force initialization
            var tenant = currentUser.getTenant();
            
            // Get all users for this tenant (only END_USER and CUSTOMER_ADMIN)
            List<User> tenantUsers = userRepository.findByTenant_TenantId(tenant.getTenantId()).stream()
                .filter(u -> u.getUserRole() == User.UserRole.END_USER || u.getUserRole() == User.UserRole.CUSTOMER_ADMIN)
                .collect(Collectors.toList());
            
            // Initialize tenant relationships to avoid lazy loading issues
            tenantUsers.forEach(u -> {
                if (u.getTenant() != null) {
                    u.getTenant().getTenantId(); // Force initialization
                    u.getTenant().getTenantName(); // Force initialization
                }
            });
            
            model.addAttribute("users", tenantUsers);
            model.addAttribute("company", company);
            model.addAttribute("tenant", tenant);
            
            // Get tenant-specific SSO config
            var ssoConfig = ssoConfigService.getByTenant(tenant);
            model.addAttribute("config", ssoConfig);
            
            return "company-admin/dashboard";
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Error loading dashboard: " + e.getMessage());
            model.addAttribute("users", new java.util.ArrayList<>());
            model.addAttribute("company", company);
            return "company-admin/dashboard";
        }
    }
    
    @GetMapping("/users/new")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String newUser(@PathVariable String company, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        // Initialize tenant to avoid lazy loading issues
        var currentUser = currentUserOpt.get();
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        
        model.addAttribute("user", new User());
        model.addAttribute("company", company);
        return "company-admin/user_form";
    }
    
    @PostMapping("/users")
    @org.springframework.transaction.annotation.Transactional
    public String createUser(@PathVariable String company, 
                             @ModelAttribute User user,
                             @RequestParam(required = false) String password,
                             RedirectAttributes ra) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        // Validate username
        if (user.getUsername() == null || user.getUsername().length() < 4) {
            ra.addFlashAttribute("error", "Username must be at least 4 characters");
            return "redirect:/" + company + "/customer-admin/users/new";
        }
        
        String usernameLower = user.getUsername().toLowerCase();
        if (userRepository.findByUsername(usernameLower).isPresent()) {
            ra.addFlashAttribute("error", "Username already exists");
            return "redirect:/" + company + "/customer-admin/users/new";
        }
        
        user.setUsername(usernameLower);
        user.setUserRole(User.UserRole.END_USER); // Customer admin can only create end users
        user.setTenant(tenant);
        user.setEnabled(true);
        
        if (password != null && !password.isEmpty()) {
            if (password.length() < 6 || password.length() > 10) {
                ra.addFlashAttribute("error", "Password must be between 6 and 10 characters");
                return "redirect:/" + company + "/customer-admin/users/new";
            }
            user.setPassword(passwordEncoder.encode(password));
        } else {
            ra.addFlashAttribute("error", "Password is required");
            return "redirect:/" + company + "/customer-admin/users/new";
        }
        
        try {
            // Ensure user has all required fields
            if (user.getUserRole() == null) {
                user.setUserRole(User.UserRole.END_USER);
            }
            userRepository.saveAndFlush(user);
            ra.addFlashAttribute("success", "User created successfully");
            return "redirect:/" + company + "/customer-admin/dashboard";
        } catch (Exception e) {
            log.error("Error creating user: ", e);
            ra.addFlashAttribute("error", "Error creating user: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
            return "redirect:/" + company + "/customer-admin/users/new";
        }
    }
    
    @GetMapping("/users/{userId}/edit")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String editUser(@PathVariable String company, @PathVariable Long userId, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        Optional<User> userOpt = userRepository.findById(userId);
        
        if (userOpt.isEmpty()) {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        User user = userOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (user.getTenant() != null) {
            user.getTenant().getTenantId(); // Force initialization
            if (!user.getTenant().getTenantId().equals(tenant.getTenantId())) {
                return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
            }
        } else {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        model.addAttribute("user", user);
        model.addAttribute("company", company);
        return "company-admin/user_form";
    }
    
    @PostMapping("/users/{userId}")
    @org.springframework.transaction.annotation.Transactional
    public String updateUser(@PathVariable String company, 
                             @PathVariable Long userId,
                             @ModelAttribute User user,
                             @RequestParam(required = false) String password,
                             RedirectAttributes ra) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        Optional<User> existingUserOpt = userRepository.findById(userId);
        
        if (existingUserOpt.isEmpty()) {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        User existingUser = existingUserOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (existingUser.getTenant() != null) {
            existingUser.getTenant().getTenantId(); // Force initialization
            if (!existingUser.getTenant().getTenantId().equals(tenant.getTenantId())) {
                return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
            }
        } else {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        // Update fields
        if (user.getEmail() != null) {
            existingUser.setEmail(user.getEmail().trim());
        }
        if (user.getFirstName() != null) {
            existingUser.setFirstName(user.getFirstName().trim());
        }
        if (user.getLastName() != null) {
            existingUser.setLastName(user.getLastName().trim());
        }
        
        // Update password if provided
        if (password != null && !password.isEmpty()) {
            if (password.length() < 6 || password.length() > 10) {
                ra.addFlashAttribute("error", "Password must be between 6 and 10 characters");
                return "redirect:/" + company + "/customer-admin/users/" + userId + "/edit";
            }
            existingUser.setPassword(passwordEncoder.encode(password));
        }
        
        // Ensure userRole is set
        if (existingUser.getUserRole() == null) {
            existingUser.setUserRole(User.UserRole.END_USER);
        }
        
        try {
            userRepository.saveAndFlush(existingUser);
            ra.addFlashAttribute("success", "User updated successfully");
            return "redirect:/" + company + "/customer-admin/dashboard";
        } catch (Exception e) {
            log.error("Error updating user: ", e);
            ra.addFlashAttribute("error", "Error updating user: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
            return "redirect:/" + company + "/customer-admin/users/" + userId + "/edit";
        }
    }
    
    @PostMapping("/users/{userId}/delete")
    @org.springframework.transaction.annotation.Transactional
    public String deleteUser(@PathVariable String company, 
                            @PathVariable Long userId,
                            RedirectAttributes ra) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        Optional<User> userOpt = userRepository.findById(userId);
        
        if (userOpt.isEmpty()) {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        User user = userOpt.get();
        // Initialize tenant to avoid lazy loading issues
        if (user.getTenant() != null) {
            user.getTenant().getTenantId(); // Force initialization
            if (!user.getTenant().getTenantId().equals(tenant.getTenantId())) {
                return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
            }
        } else {
            return "redirect:/" + company + "/customer-admin/dashboard?error=user_not_found";
        }
        
        // Prevent deleting customer-admin users
        if (user.getUserRole() == User.UserRole.CUSTOMER_ADMIN) {
            ra.addFlashAttribute("error", "Cannot delete customer-admin users");
            return "redirect:/" + company + "/customer-admin/dashboard";
        }
        
        userRepository.deleteById(userId);
        ra.addFlashAttribute("success", "User deleted successfully");
        return "redirect:/" + company + "/customer-admin/dashboard";
    }
    
    @PostMapping("/sso/toggle")
    @org.springframework.transaction.annotation.Transactional
    public String toggleSSO(@PathVariable String company,
                            @RequestParam boolean enabled,
                            RedirectAttributes ra) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        ssoConfigService.toggleForTenant(enabled, tenant);
        ra.addFlashAttribute("success", "SSO " + (enabled ? "enabled" : "disabled") + " successfully");
        return "redirect:/" + company + "/customer-admin/dashboard";
    }
    
    @PostMapping("/sso/config")
    @org.springframework.transaction.annotation.Transactional
    public String saveSSOConfig(@PathVariable String company,
                                @ModelAttribute com.example.finalsso.entity.SSOConfig config,
                                RedirectAttributes ra) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }
        
        var currentUser = currentUserOpt.get();
        if (currentUser.getTenant() != null) {
            currentUser.getTenant().getTenantId(); // Force initialization
        }
        var tenant = currentUser.getTenant();
        
        try {
            ssoConfigService.saveForTenant(config, tenant);
            ra.addFlashAttribute("success", "SSO configuration saved successfully");
        } catch (Exception e) {
            log.error("Error saving SSO config: ", e);
            ra.addFlashAttribute("error", "Error saving SSO configuration: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
        }
        return "redirect:/" + company + "/customer-admin/dashboard";
    }
}

