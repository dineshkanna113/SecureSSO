package com.example.finalsso.config;

import com.example.finalsso.service.UserCompanyMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter to validate company context in URL matches authenticated user's company
 */
public class CompanyContextFilter extends OncePerRequestFilter {
    
    private final UserCompanyMapper userCompanyMapper;
    
    public CompanyContextFilter(UserCompanyMapper userCompanyMapper) {
        this.userCompanyMapper = userCompanyMapper;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        
        // Skip filter for super-admin routes and other non-company routes
        if (path.startsWith("/super-admin") || 
            path.startsWith("/login") || 
            path.startsWith("/register") ||
            path.startsWith("/sso") ||
            path.startsWith("/api") ||
            path.startsWith("/admin") ||
            path.startsWith("/user") ||
            path.startsWith("/css") ||
            path.startsWith("/js") ||
            path.startsWith("/images") ||
            path.startsWith("/test")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Skip filter for password pages - they're part of the login flow and user is not authenticated yet
        if (path.endsWith("/password") || path.contains("/password")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Extract company name from path like /{company}/customer-admin/** or /{company}/enduser/**
        String companyName = extractCompanyFromPath(path);
        
        if (companyName != null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            // Only validate company context for authenticated users (not during login flow)
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                String username = auth.getName();
                if (!userCompanyMapper.validateCompanyContext(username, companyName)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied: Company context mismatch");
                    return;
                }
            }
            // If not authenticated, allow access (will be handled by Spring Security)
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractCompanyFromPath(String path) {
        // Match patterns like /{company}/customer-admin/** or /{company}/enduser/**
        if (path.startsWith("/") && path.length() > 1) {
            String[] parts = path.substring(1).split("/");
            if (parts.length >= 2) {
                String secondPart = parts[1];
                if ("customer-admin".equals(secondPart) || "enduser".equals(secondPart) || "password".equals(secondPart)) {
                    return parts[0]; // First part is company name
                }
            }
        }
        return null;
    }
}

