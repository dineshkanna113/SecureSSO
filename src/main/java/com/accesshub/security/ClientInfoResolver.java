package com.accesshub.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class ClientInfoResolver {

    public String getClientIp(HttpServletRequest request) {
        if (request == null) return "unknown";
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        String addr = request.getRemoteAddr();
        return addr != null ? addr : "unknown";
    }

    public String getUserAgent(HttpServletRequest request) {
        if (request == null) return "unknown";
        String ua = request.getHeader("User-Agent");
        return ua != null ? ua : "unknown";
    }
}
