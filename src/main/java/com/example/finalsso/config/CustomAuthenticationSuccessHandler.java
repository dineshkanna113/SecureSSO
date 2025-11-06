package com.example.finalsso.config;

import com.example.finalsso.service.UserCompanyMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Custom authentication success handler that redirects based on stored target URL or user role
 */
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    
    private final UserCompanyMapper userCompanyMapper;
    
    public CustomAuthenticationSuccessHandler(UserCompanyMapper userCompanyMapper) {
        this.userCompanyMapper = userCompanyMapper;
        setAlwaysUseDefaultTargetUrl(false);
    }
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                       Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        String targetUrl = null;
        String username = authentication != null ? authentication.getName() : "unknown";
        
        System.out.println("CustomAuthenticationSuccessHandler: User authenticated: " + username);
        System.out.println("CustomAuthenticationSuccessHandler: Authorities: " + 
            (authentication != null ? authentication.getAuthorities() : "null"));
        
        // Check if there's a stored target URL from password page
        if (session != null) {
            targetUrl = (String) session.getAttribute("target_url");
            System.out.println("CustomAuthenticationSuccessHandler: Target URL from session: " + targetUrl);
            if (targetUrl != null) {
                session.removeAttribute("target_url");
            }
        }
        
        // If no target URL, determine based on user role
        if (targetUrl == null || targetUrl.isEmpty()) {
            try {
                targetUrl = userCompanyMapper.getRedirectPath(username);
                System.out.println("CustomAuthenticationSuccessHandler: Redirect path from mapper: " + targetUrl);
            } catch (Exception e) {
                System.err.println("CustomAuthenticationSuccessHandler: Error getting redirect path: " + e.getMessage());
                e.printStackTrace();
                // Fallback: check authentication authorities
                if (authentication != null) {
                    boolean isSuperAdmin = authentication.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                    boolean isCustomerAdmin = authentication.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_CUSTOMER_ADMIN"));
                    boolean isEndUser = authentication.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_END_USER"));
                    
                    System.out.println("CustomAuthenticationSuccessHandler: Fallback - isSuperAdmin=" + isSuperAdmin + 
                        ", isCustomerAdmin=" + isCustomerAdmin + ", isEndUser=" + isEndUser);
                    
                    if (isSuperAdmin) {
                        targetUrl = "/super-admin/dashboard";
                    } else if (isCustomerAdmin || isEndUser) {
                        // Try to get company name from user
                        try {
                            var companyOpt = userCompanyMapper.getCompanyName(username);
                            if (companyOpt.isPresent()) {
                                String company = companyOpt.get();
                                if (isCustomerAdmin) {
                                    targetUrl = "/" + company + "/customer-admin/dashboard";
                                } else {
                                    targetUrl = "/" + company + "/enduser/dashboard";
                                }
                            } else {
                                targetUrl = "/login?error=no_company_assigned";
                            }
                        } catch (Exception ex) {
                            targetUrl = "/login?error=redirect_failed";
                        }
                    } else {
                        targetUrl = "/login?error=unknown_role";
                    }
                } else {
                    targetUrl = "/login?error=not_authenticated";
                }
            }
        }
        
        // Clear login username from session
        if (session != null) {
            session.removeAttribute("login_username");
        }
        
        System.out.println("CustomAuthenticationSuccessHandler: Final redirect URL: " + targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}

