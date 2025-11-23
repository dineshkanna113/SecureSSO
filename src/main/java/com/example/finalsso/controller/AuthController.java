package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.SSOProviderRepository;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.service.UserCompanyMapper;
import com.example.finalsso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.List;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private SSOConfigService ssoConfigService;

    @Autowired
    private UserCompanyMapper userCompanyMapper;
    
    @Autowired
    private TenantRepository tenantRepository;
    
    @Autowired
    private SSOProviderRepository ssoProviderRepository;
    
    @Autowired
    private com.example.finalsso.service.CustomerAdminRequestService customerAdminRequestService;

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, 
                               @RequestParam(required = false) String companyName,
                               Model model) {
        try {
            userService.register(user, companyName);
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("user", user);
            model.addAttribute("companyName", companyName);
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }
    
    @PostMapping("/register/admin-request")
    public String registerAdminRequest(@RequestParam String firstName,
                                       @RequestParam String lastName,
                                       @RequestParam String email,
                                       @RequestParam String companyName,
                                       @RequestParam(required = false) String username,
                                       @RequestParam(required = false) String password,
                                       @RequestParam(required = false) String message,
                                       Model model) {
        try {
            customerAdminRequestService.createRequest(firstName, lastName, email, companyName, username, password, message);
            model.addAttribute("user", new User());
            model.addAttribute("success", "Your request has been submitted successfully. You will receive an email notification once it's reviewed.");
            return "register";
        } catch (IllegalArgumentException e) {
            model.addAttribute("user", new User());
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "logout", required = false) String logout,
                            Model model) {
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }
        if (error != null) {
            model.addAttribute("error", "Invalid username or password.");
        }
        return "login";
    }

    @PostMapping("/login/username")
    public String handleUsername(@RequestParam("username") String username, 
                                HttpSession session, Model model) {
        var userInfo = userCompanyMapper.getUserInfo(username);
        if (userInfo.isEmpty()) {
            model.addAttribute("error", "User not found");
            return "login";
        }
        
        // Store username in session for password verification
        session.setAttribute("login_username", username);
        
        // Redirect to appropriate password page
        String passwordPath = userCompanyMapper.getPasswordPagePath(username);
        return "redirect:" + passwordPath;
    }

    @GetMapping("/super-admin/password")
    public String superAdminPasswordPage(HttpSession session, Model model) {
        String username = (String) session.getAttribute("login_username");
        if (username == null) {
            return "redirect:/login?error=session_expired";
        }
        
        var userInfo = userCompanyMapper.getUserInfo(username);
        if (userInfo.isEmpty() || userInfo.get().role != User.UserRole.SUPER_ADMIN) {
            return "redirect:/login?error=invalid_user";
        }
        
        // Store target URL for after authentication
        session.setAttribute("target_url", "/super-admin/dashboard");
        
        model.addAttribute("username", username);
        model.addAttribute("companyName", "Super Admin");
        return "password";
    }

    @GetMapping("/{company}/password")
    public String companyPasswordPage(@PathVariable String company, 
                                     HttpSession session, Model model) {
        String username = (String) session.getAttribute("login_username");
        if (username == null) {
            return "redirect:/login?error=session_expired";
        }
        
        var userInfo = userCompanyMapper.getUserInfo(username);
        if (userInfo.isEmpty()) {
            return "redirect:/login?error=invalid_user";
        }
        
        // Validate company context
        if (!userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=company_mismatch";
        }
        
        // Store target URL based on role
        String targetUrl;
        if (userInfo.get().role == User.UserRole.CUSTOMER_ADMIN) {
            targetUrl = "/" + company + "/customer-admin/dashboard";
        } else {
            targetUrl = "/" + company + "/enduser/dashboard";
        }
        session.setAttribute("target_url", targetUrl);
        
        // Get tenant-specific SSO config and providers
        if (userInfo.get().tenantId != null) {
            var tenantOpt = tenantRepository.findById(userInfo.get().tenantId);
            if (tenantOpt.isPresent()) {
                var tenant = tenantOpt.get();
                com.example.finalsso.entity.SSOConfig ssoConfig = ssoConfigService.getByTenant(tenant);
                model.addAttribute("ssoConfig", ssoConfig);
                model.addAttribute("ssoEnabled", ssoConfig.isSsoEnabled());
                model.addAttribute("ssoProtocol", ssoConfig.getActiveProtocol());
                
                // Get active SSO providers for this tenant
                if (ssoConfig.isSsoEnabled()) {
                    List<SSOProvider> providers = ssoProviderRepository.findByTenant(tenant).stream()
                            .filter(SSOProvider::isActive)
                            .collect(java.util.stream.Collectors.toList());
                    model.addAttribute("ssoProviders", providers);
                } else {
                    model.addAttribute("ssoProviders", new java.util.ArrayList<>());
                }
            } else {
                model.addAttribute("ssoEnabled", false);
                model.addAttribute("ssoProviders", new java.util.ArrayList<>());
            }
        } else {
            model.addAttribute("ssoEnabled", false);
            model.addAttribute("ssoProviders", new java.util.ArrayList<>());
        }
        
        model.addAttribute("username", username);
        model.addAttribute("companyName", userInfo.get().companyDisplayName != null ? userInfo.get().companyDisplayName : userInfo.get().companySlug);
        model.addAttribute("company", company);
        return "password";
    }


    @GetMapping("/login/sso")
    public String loginSso(Model model) {
        model.addAttribute("config", ssoConfigService.get());
        return "login_sso";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access_denied";
    }
}
