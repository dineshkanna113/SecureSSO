package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.SSOProviderRepository;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/{company}/customer-admin")
public class CompanyAdminController {

    private static final Logger log = LoggerFactory.getLogger(CompanyAdminController.class);

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final SSOProviderRepository ssoProviderRepository;
    private final SSOConfigService ssoConfigService;
    private final UserService userService;
    private final UserCompanyMapper userCompanyMapper;
    private final PasswordEncoder passwordEncoder;

    public CompanyAdminController(UserRepository userRepository,
                                  TenantRepository tenantRepository,
                                  SSOProviderRepository ssoProviderRepository,
                                  SSOConfigService ssoConfigService,
                                  UserService userService,
                                  UserCompanyMapper userCompanyMapper,
                                  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.ssoProviderRepository = ssoProviderRepository;
        this.ssoConfigService = ssoConfigService;
        this.userService = userService;
        this.userCompanyMapper = userCompanyMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/dashboard")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String dashboard(@PathVariable String company, Model model, HttpServletRequest request) {
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

            // Get tenant-specific SSO providers
            List<SSOProvider> ssoProviders = ssoProviderRepository.findByTenant(tenant);
            model.addAttribute("ssoProviders", ssoProviders);
            
            // Check for test results in session
            HttpSession session = request.getSession(false);
            if (session != null && Boolean.TRUE.equals(session.getAttribute("test_success"))) {
                model.addAttribute("testSuccess", true);
                model.addAttribute("testProtocol", session.getAttribute("test_protocol"));
                model.addAttribute("testNameId", session.getAttribute("test_nameId"));
                model.addAttribute("testAttributes", session.getAttribute("test_attributes"));
                // Clear test attributes after reading
                session.removeAttribute("test_success");
                session.removeAttribute("test_protocol");
                session.removeAttribute("test_nameId");
                session.removeAttribute("test_attributes");
            }

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

    // SSO Provider Management Endpoints
    @GetMapping("/sso/providers")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    @ResponseBody
    public List<SSOProvider> listProviders(@PathVariable String company) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return new java.util.ArrayList<>();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return new java.util.ArrayList<>();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization
        return ssoProviderRepository.findByTenant(tenant);
    }

    @GetMapping("/sso/providers/{id}")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    @ResponseBody
    public ResponseEntity<SSOProvider> getProvider(@PathVariable String company, @PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> providerOpt = ssoProviderRepository.findById(id);
        if (providerOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        SSOProvider provider = providerOpt.get();
        if (provider.getTenant() == null || !provider.getTenant().getTenantId().equals(tenant.getTenantId())) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(provider);
    }

    @PostMapping("/sso/providers")
    @org.springframework.transaction.annotation.Transactional
    @ResponseBody
    public ResponseEntity<?> createProvider(@PathVariable String company, @RequestBody SSOProvider provider) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        if (provider.getName() == null || provider.getName().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Provider name is required"));
        }
        provider.setName(provider.getName().trim());

        String normalizedType = normalizeProviderType(provider.getType());
        if (normalizedType == null) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Provider type is required"));
        }
        provider.setType(normalizedType);

        // Check for duplicate name within tenant
        if (ssoProviderRepository.existsByNameIgnoreCaseAndTenant(provider.getName().trim(), tenant)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.CONFLICT).body(java.util.Map.of("error", "Provider name already exists"));
        }

        provider.setTenant(tenant);
        provider.setActive(false);
        provider.setType(normalizedType);
        try {
            SSOProvider saved = ssoProviderRepository.saveAndFlush(provider);
            return ResponseEntity.status(org.springframework.http.HttpStatus.CREATED).body(saved);
        } catch (DataIntegrityViolationException dive) {
            log.error("Constraint violation while creating SSO provider", dive);
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST)
                    .body(java.util.Map.of("error", "Unable to save provider data. Ensure large metadata/certificates fit your database configuration."));
        } catch (Exception e) {
            log.error("Error creating SSO provider: ", e);
            return ResponseEntity.status(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(java.util.Map.of("error", "Failed to create provider: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage())));
        }
    }

    @PutMapping("/sso/providers/{id}")
    @org.springframework.transaction.annotation.Transactional
    @ResponseBody
    public ResponseEntity<?> updateProvider(@PathVariable String company, @PathVariable Long id, @RequestBody SSOProvider incoming) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> existingOpt = ssoProviderRepository.findById(id);
        if (existingOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        SSOProvider existing = existingOpt.get();
        if (existing.getTenant() == null || !existing.getTenant().getTenantId().equals(tenant.getTenantId())) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        String newName = incoming.getName() != null ? incoming.getName().trim() : null;
        if (newName == null || newName.isEmpty()) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Provider name is required"));
        }

        // Check for duplicate name within tenant (excluding current provider)
        Optional<SSOProvider> clashOpt = ssoProviderRepository.findByNameIgnoreCaseAndTenant(newName, tenant);
        if (clashOpt.isPresent() && !clashOpt.get().getId().equals(id)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.CONFLICT).body(java.util.Map.of("error", "Provider name already exists"));
        }

        // Update fields
        existing.setName(newName);
        String normalizedType = normalizeProviderType(incoming.getType());
        if (normalizedType == null) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Provider type is required"));
        }
        existing.setType(normalizedType);
        existing.setOidcClientId(incoming.getOidcClientId());
        existing.setOidcClientSecret(incoming.getOidcClientSecret());
        existing.setOidcIssuerUri(incoming.getOidcIssuerUri());
        existing.setOidcRedirectUri(incoming.getOidcRedirectUri());
        existing.setOidcScopes(incoming.getOidcScopes());
        existing.setOidcAuthorizationEndpoint(incoming.getOidcAuthorizationEndpoint());
        existing.setOidcTokenEndpoint(incoming.getOidcTokenEndpoint());
        existing.setOidcUserInfoEndpoint(incoming.getOidcUserInfoEndpoint());
        existing.setOidcLogoutEndpoint(incoming.getOidcLogoutEndpoint());
        existing.setSamlEntityId(incoming.getSamlEntityId());
        existing.setSamlSsoUrl(incoming.getSamlSsoUrl());
        existing.setSamlX509Cert(incoming.getSamlX509Cert());
        existing.setSamlMetadataXml(incoming.getSamlMetadataXml());
        existing.setSamlMetadataUrl(incoming.getSamlMetadataUrl());
        existing.setJwtIssuer(incoming.getJwtIssuer());
        existing.setJwtAudience(incoming.getJwtAudience());
        existing.setJwtJwksUri(incoming.getJwtJwksUri());
        existing.setJwtHeaderName(incoming.getJwtHeaderName());
        existing.setJwtCertificate(incoming.getJwtCertificate());
        existing.setJwtSsoUrl(incoming.getJwtSsoUrl());
        existing.setJwtClientId(incoming.getJwtClientId());
        existing.setJwtClientSecret(incoming.getJwtClientSecret());
        existing.setJwtRedirectUri(incoming.getJwtRedirectUri());

        try {
            SSOProvider saved = ssoProviderRepository.saveAndFlush(existing);
            return ResponseEntity.ok(saved);
        } catch (DataIntegrityViolationException dive) {
            log.error("Constraint violation while updating SSO provider", dive);
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST)
                    .body(java.util.Map.of("error", "Unable to save provider data. Ensure large metadata/certificates fit your database configuration."));
        } catch (Exception e) {
            log.error("Error updating SSO provider: ", e);
            return ResponseEntity.status(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(java.util.Map.of("error", "Failed to update provider: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage())));
        }
    }

    @DeleteMapping("/sso/providers/{id}")
    @org.springframework.transaction.annotation.Transactional
    @ResponseBody
    public ResponseEntity<?> deleteProvider(@PathVariable String company, @PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> providerOpt = ssoProviderRepository.findById(id);
        if (providerOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        SSOProvider provider = providerOpt.get();
        if (provider.getTenant() == null || !provider.getTenant().getTenantId().equals(tenant.getTenantId())) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        ssoProviderRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/sso/providers/{id}/activate")
    @org.springframework.transaction.annotation.Transactional
    @ResponseBody
    public ResponseEntity<?> activateProvider(@PathVariable String company, @PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> providerOpt = ssoProviderRepository.findById(id);
        if (providerOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        SSOProvider provider = providerOpt.get();
        if (provider.getTenant() == null || !provider.getTenant().getTenantId().equals(tenant.getTenantId())) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        provider.setActive(true);
        ssoProviderRepository.save(provider);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/sso/providers/{id}/deactivate")
    @org.springframework.transaction.annotation.Transactional
    @ResponseBody
    public ResponseEntity<?> deactivateProvider(@PathVariable String company, @PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> providerOpt = ssoProviderRepository.findById(id);
        if (providerOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        SSOProvider provider = providerOpt.get();
        if (provider.getTenant() == null || !provider.getTenant().getTenantId().equals(tenant.getTenantId())) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        provider.setActive(false);
        ssoProviderRepository.save(provider);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/sso/providers/{id}/test")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String testProvider(@PathVariable String company, @PathVariable Long id, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return "redirect:/login?error=invalid_user";
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        Optional<SSOProvider> providerOpt = ssoProviderRepository.findById(id);
        if (providerOpt.isEmpty() || providerOpt.get().getTenant() == null || !providerOpt.get().getTenant().getTenantId().equals(tenant.getTenantId())) {
            return "redirect:/" + company + "/customer-admin/dashboard?error=provider_not_found";
        }

        SSOProvider provider = providerOpt.get();
        
        // Set test flag in session
        HttpSession session = request.getSession(true);
        session.setAttribute("sso_test", true);
        session.setAttribute("sso_test_company", company);
        session.setAttribute("sso_test_provider_id", id);
        
        // Redirect to appropriate SSO flow based on provider type
        String providerType = provider.getType() != null ? provider.getType().toUpperCase() : "";
        if ("SAML".equals(providerType)) {
            session.setAttribute("saml_test", true);
            session.setAttribute("saml_test_provider_id", id);
            return "redirect:/sso/saml2/authenticate?providerId=" + id;
        } else if ("OIDC".equals(providerType)) {
            session.setAttribute("oidc_test", true);
            session.setAttribute("oidc_test_provider_id", id);
            return "redirect:/sso/oauth2/authorize?providerId=" + id;
        } else if ("JWT".equals(providerType)) {
            session.setAttribute("jwt_test", true);
            session.setAttribute("jwt_test_provider_id", id);
            return "redirect:/sso/jwt/authenticate?providerId=" + id;
        }
        
        return "redirect:/" + company + "/customer-admin/dashboard?error=unsupported_provider_type";
    }

    @GetMapping("/sso/metadata")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    @ResponseBody
    public ResponseEntity<?> getMetadata(@PathVariable String company, 
                                         @RequestParam(required = false, defaultValue = "SAML") String type,
                                         HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;

        if (username == null || !userCompanyMapper.validateCompanyContext(username, company)) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        Optional<User> currentUserOpt = userRepository.findByUsername(username);
        if (currentUserOpt.isEmpty() || currentUserOpt.get().getTenant() == null) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN).build();
        }

        var tenant = currentUserOpt.get().getTenant();
        tenant.getTenantId(); // Force initialization

        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
        String normalizedType = type != null ? type.toUpperCase() : "SAML";

        if ("SAML".equals(normalizedType)) {
            String spEntityId = baseUrl + "/" + company;
            String acsUrl = baseUrl + "/" + company + "/sso/saml2/acs";

            // Generate SAML metadata XML
            String metadata = String.format(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\">\n" +
                "  <md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n" +
                "    <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"%s\" index=\"0\"/>\n" +
                "  </md:SPSSODescriptor>\n" +
                "</md:EntityDescriptor>",
                spEntityId, acsUrl
            );

            return ResponseEntity.ok()
                    .header("Content-Type", "application/xml")
                    .body(metadata);
        } else if ("OIDC".equals(normalizedType) || "OAUTH2".equals(normalizedType)) {
            // Return OIDC/OAuth2 metadata as JSON with company-specific redirect URI
            String redirectUri = baseUrl + "/" + company + "/sso/oauth2/callback";
            java.util.Map<String, Object> metadata = new java.util.HashMap<>();
            metadata.put("redirect_uri", redirectUri);
            metadata.put("authorization_endpoint", baseUrl + "/sso/oauth2/authorize");
            metadata.put("token_endpoint", baseUrl + "/sso/oauth2/callback");
            metadata.put("response_types_supported", java.util.Arrays.asList("code"));
            metadata.put("scopes_supported", java.util.Arrays.asList("openid", "profile", "email"));
            
            return ResponseEntity.ok()
                    .header("Content-Type", "application/json")
                    .body(metadata);
        } else if ("JWT".equals(normalizedType)) {
            // Return JWT metadata as JSON with company-specific redirect URI
            String redirectUri = baseUrl + "/" + company + "/sso/jwt/callback";
            java.util.Map<String, Object> metadata = new java.util.HashMap<>();
            metadata.put("redirect_uri", redirectUri);
            metadata.put("callback_endpoint", redirectUri);
            metadata.put("token_format", "JWT");
            
            return ResponseEntity.ok()
                    .header("Content-Type", "application/json")
                    .body(metadata);
        }

        return ResponseEntity.badRequest().body("Unsupported metadata type: " + type);
    }

    private String normalizeProviderType(String rawType) {
        if (rawType == null) {
            return null;
        }
        String value = rawType.trim().toUpperCase();
        if (value.startsWith("OIDC")) {
            return "OIDC";
        }
        if (value.startsWith("SAML")) {
            return "SAML";
        }
        if (value.startsWith("JWT")) {
            return "JWT";
        }
        return null;
    }
}