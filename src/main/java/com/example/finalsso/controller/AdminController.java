package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin")
public class AdminController {

	private final UserRepository userRepository;
	private final TenantRepository tenantRepository;
	private final SSOConfigService ssoConfigService;
	private final PasswordEncoder passwordEncoder;
	private final UserService userService;

	public AdminController(UserRepository userRepository, TenantRepository tenantRepository,
	                       SSOConfigService ssoConfigService, 
	                       PasswordEncoder passwordEncoder, UserService userService) {
		this.userRepository = userRepository;
		this.tenantRepository = tenantRepository;
		this.ssoConfigService = ssoConfigService;
		this.passwordEncoder = passwordEncoder;
		this.userService = userService;
	}

	@GetMapping("/dashboard")
	public String dashboard(Model model) {
		// Use tenant-aware user service to get accessible users
		model.addAttribute("users", userService.getAccessibleUsers());
		model.addAttribute("config", ssoConfigService.get());
		return "admin/dashboard";
	}

	@GetMapping("/users/new")
	public String newUser(Model model) {
		model.addAttribute("user", new User());
		return "admin/user_form";
	}

	@PostMapping("/users")
    public String createUser(@ModelAttribute User user, 
                            @RequestParam(required = false) String companyName,
                            org.springframework.ui.Model model) {
        // Validate username: lowercase only, min 4 chars, alphanumeric + underscore
        String username = user.getUsername();
        if (username == null || username.length() < 4) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Username must be at least 4 characters long");
            return "admin/user_form";
        }
        String usernameLower = username.toLowerCase();
        if (!username.equals(usernameLower) || !usernameLower.matches("^[a-z0-9_]+$")) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Username must be lowercase and contain only letters, numbers, and underscores");
            return "admin/user_form";
        }
        user.setUsername(usernameLower);
        
        java.util.Optional<com.example.finalsso.entity.User> existingByUsername = userRepository.findByUsername(user.getUsername());
        if (existingByUsername.isPresent()) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Username already exists");
            return "admin/user_form";
        }
        
        // Validate and set role
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("ROLE_END_USER");
        }
        
        // Validate password
        String password = user.getPassword();
        if (password == null || password.isEmpty()) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Password is required");
            return "admin/user_form";
        }
        if (password.length() < 6 || password.length() > 10) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Password must be between 6 and 10 characters");
            return "admin/user_form";
        }
        user.setPassword(passwordEncoder.encode(password));
        
        // Handle tenant assignment based on role
        if (user.getUserRole() == User.UserRole.SUPER_ADMIN) {
            user.setTenant(null); // Super admin has no tenant
        } else if (user.getUserRole() == User.UserRole.CUSTOMER_ADMIN || user.getUserRole() == User.UserRole.END_USER) {
            if (companyName == null || companyName.trim().isEmpty()) {
                model.addAttribute("user", user);
                model.addAttribute("error", "Company name is required for Customer Admin and End User");
                return "admin/user_form";
            }
            // Find or create tenant
            com.example.finalsso.entity.Tenant tenant = tenantRepository.findByTenantName(companyName.trim())
                .orElseGet(() -> {
                    com.example.finalsso.entity.Tenant newTenant = new com.example.finalsso.entity.Tenant();
                    newTenant.setTenantName(companyName.trim());
                    org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                    String createdBy = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName()) 
                        ? auth.getName() : "system";
                    newTenant.setCreatedBy(createdBy);
                    newTenant.setActive(true);
                    return tenantRepository.save(newTenant);
                });
            user.setTenant(tenant);
        }
        
        userRepository.save(user);
        return "redirect:/admin/dashboard";
    }

	@GetMapping("/users/{id}/edit")
	public String editUser(@PathVariable Long id, Model model) {
		User user = userRepository.findById(id).orElseThrow();
		model.addAttribute("user", user);
		return "admin/user_form";
	}

	@PostMapping("/users/{id}")
    public String updateUser(@PathVariable Long id, @ModelAttribute User user, 
                            @RequestParam(required = false) String companyName,
                            org.springframework.ui.Model model) {
        // Check if current user can access this user
        if (!userService.canAccessUser(id)) {
            return "redirect:/admin/dashboard?error=access_denied";
        }
        
        User existing = userRepository.findById(id).orElseThrow();
        java.util.Optional<com.example.finalsso.entity.User> clash = userRepository.findByUsername(user.getUsername());
        if (clash.isPresent() && !clash.get().getId().equals(id)) {
            user.setId(id);
            model.addAttribute("user", user);
            model.addAttribute("error", "Username already exists");
            return "admin/user_form";
        }
        // Validate username: lowercase only, min 4 chars, alphanumeric + underscore
        String username = user.getUsername();
        if (username == null || username.length() < 4) {
            model.addAttribute("user", existing);
            model.addAttribute("error", "Username must be at least 4 characters long");
            return "admin/user_form";
        }
        String usernameLower = username.toLowerCase();
        if (!username.equals(usernameLower) || !usernameLower.matches("^[a-z0-9_]+$")) {
            model.addAttribute("user", existing);
            model.addAttribute("error", "Username must be lowercase and contain only letters, numbers, and underscores");
            return "admin/user_form";
        }
        
        existing.setUsername(usernameLower);
        existing.setEmail(user.getEmail());
        existing.setFirstName(user.getFirstName());
        existing.setLastName(user.getLastName());
        existing.setRole(user.getRole()); // This will set userRole enum from String
        existing.setEnabled(user.isEnabled());
        
        // Update password if provided
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            if (user.getPassword().length() < 6 || user.getPassword().length() > 10) {
                model.addAttribute("user", existing);
                model.addAttribute("error", "Password must be between 6 and 10 characters");
                return "admin/user_form";
            }
            existing.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        
        // Handle tenant assignment based on role
        if (existing.getUserRole() == User.UserRole.SUPER_ADMIN) {
            existing.setTenant(null); // Super admin has no tenant
        } else if (existing.getUserRole() == User.UserRole.CUSTOMER_ADMIN || existing.getUserRole() == User.UserRole.END_USER) {
            if (companyName != null && !companyName.trim().isEmpty()) {
                // Find or create tenant
                com.example.finalsso.entity.Tenant tenant = tenantRepository.findByTenantName(companyName.trim())
                    .orElseGet(() -> {
                        com.example.finalsso.entity.Tenant newTenant = new com.example.finalsso.entity.Tenant();
                        newTenant.setTenantName(companyName.trim());
                        org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                        String createdBy = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName()) 
                            ? auth.getName() : "system";
                        newTenant.setCreatedBy(createdBy);
                        newTenant.setActive(true);
                        return tenantRepository.save(newTenant);
                    });
                existing.setTenant(tenant);
            } else if (existing.getTenant() == null) {
                model.addAttribute("user", existing);
                model.addAttribute("error", "Company name is required for Customer Admin and End User");
                return "admin/user_form";
            }
        }
        
        userRepository.save(existing);
        return "redirect:/admin/dashboard";
    }

	@PostMapping("/users/{id}/delete")
	public String deleteUser(@PathVariable Long id, org.springframework.web.servlet.mvc.support.RedirectAttributes ra) {
		// Check if current user can access this user
		if (!userService.canAccessUser(id)) {
			ra.addFlashAttribute("error", "You do not have permission to delete this user.");
			return "redirect:/admin/dashboard";
		}
		
		User u = userRepository.findById(id).orElse(null);
		if (u != null && u.getUserRole() == User.UserRole.SUPER_ADMIN) {
			long admins = userRepository.countByUserRole(User.UserRole.SUPER_ADMIN);
			if (admins <= 1) {
				ra.addFlashAttribute("error", "Cannot delete the last super administrator.");
				return "redirect:/admin/dashboard";
			}
		}
		userRepository.deleteById(id);
		return "redirect:/admin/dashboard";
	}
}


