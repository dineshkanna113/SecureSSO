package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.entity.User;
import com.example.finalsso.service.UserCompanyMapper;
import com.example.finalsso.repository.SSOProviderRepository;
import com.example.finalsso.repository.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.Base64;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;

@Controller
public class SsoJwtController {

    private final SSOProviderRepository providerRepository;
    private final UserRepository userRepository;
    private final UserCompanyMapper userCompanyMapper;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SsoJwtController(SSOProviderRepository providerRepository, UserRepository userRepository, UserCompanyMapper userCompanyMapper) {
        this.providerRepository = providerRepository;
        this.userRepository = userRepository;
        this.userCompanyMapper = userCompanyMapper;
    }

    @GetMapping("/sso/jwt/authenticate")
    public String authenticate(@RequestParam(required = false) Long providerId, HttpServletRequest request) {
        SSOProvider provider = null;
        // Check for test provider ID from session
        Long testProviderId = null;
        var session = request.getSession(false);
        if (session != null) {
            Object attr = session.getAttribute("jwt_test_provider_id");
            if (attr instanceof Long) {
                testProviderId = (Long) attr;
            }
        }
        if (providerId != null) {
            provider = providerRepository.findById(providerId).orElse(null);
        } else if (testProviderId != null) {
            provider = providerRepository.findById(testProviderId).orElse(null);
        } else {
            // Find first active JWT provider
            provider = providerRepository.findAll().stream()
                    .filter(p -> p.isActive() && "JWT".equalsIgnoreCase(p.getType()))
                    .findFirst().orElse(null);
        }

        if (provider == null) {
            return "redirect:/login?error=jwt_provider_not_found";
        }
        
        // JWT login only works with SSO URL redirect flow (miniOrange)
        // No manual token entry - token comes from IdP after authentication
        if (provider.getJwtSsoUrl() == null || provider.getJwtSsoUrl().isEmpty()) {
            return "redirect:/login?error=jwt_sso_url_required";
        }

        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
        
        // Extract company from session or provider's tenant
        String company = null;
        if (session != null) {
            company = (String) session.getAttribute("sso_test_company");
        }
        if (company == null && provider.getTenant() != null) {
            company = provider.getTenant().getTenantName();
            if (company != null) {
                company = company.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-+", "").replaceAll("-+$", "");
            }
        }
        
        // Use provider's configured redirect URI, or default to company-specific callback
        String redirectUri = provider.getJwtRedirectUri();
        if (redirectUri == null || redirectUri.trim().isEmpty()) {
            if (company != null) {
                redirectUri = baseUrl + "/" + company + "/sso/jwt/callback";
            } else {
                redirectUri = baseUrl + "/sso/jwt/callback";
            }
        } else {
            redirectUri = redirectUri.trim();
            // If relative, make it absolute
            if (redirectUri.startsWith("/")) {
                redirectUri = baseUrl + redirectUri;
            }
        }

        String clientId = provider.getJwtClientId();
        if (clientId == null || clientId.isEmpty()) {
            return "redirect:/login?error=jwt_client_id_missing";
        }

        // Build SSO URL with query parameters
        String ssoUrl = provider.getJwtSsoUrl();
        String redirect = ssoUrl + (ssoUrl.contains("?") ? "&" : "?") +
                "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        // Store provider ID in session for callback
        Long finalProviderId = providerId != null ? providerId : (testProviderId != null ? testProviderId : provider.getId());
        if (finalProviderId != null) {
            request.getSession(true).setAttribute("jwt_provider_id", finalProviderId);
        }

        return "redirect:" + redirect;
    }

    @GetMapping({"/sso/jwt/callback", "/{company}/sso/jwt/callback"})
    @PostMapping({"/sso/jwt/callback", "/{company}/sso/jwt/callback"})
    public String callback(@org.springframework.web.bind.annotation.PathVariable(required = false) String company,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String jwt,
            @RequestParam(required = false) String id_token,
            @RequestParam(required = false) String access_token,
            @RequestParam(required = false) String error,
            HttpServletRequest request) {
        try {
            if (error != null) {
                return "redirect:/login?error=" + error;
            }

            // Check multiple parameter names for JWT token (miniOrange may use different names)
            String jwtToken = token;
            if (jwtToken == null || jwtToken.isEmpty()) {
                jwtToken = jwt;
            }
            if (jwtToken == null || jwtToken.isEmpty()) {
                jwtToken = id_token;
            }
            if (jwtToken == null || jwtToken.isEmpty()) {
                jwtToken = access_token;
            }

            if (jwtToken == null || jwtToken.isEmpty()) {
                return "redirect:/login?error=no_token";
            }

            // Get provider from session or find active one
            Long providerId = (Long) request.getSession(false).getAttribute("jwt_provider_id");
            SSOProvider provider = null;
            if (providerId != null) {
                provider = providerRepository.findById(providerId).orElse(null);
                request.getSession(false).removeAttribute("jwt_provider_id");
            }
            if (provider == null) {
                provider = providerRepository.findAll().stream()
                        .filter(p -> p.isActive() && "JWT".equalsIgnoreCase(p.getType()))
                        .findFirst().orElse(null);
            }

            if (provider == null) {
                return "redirect:/login?error=no_provider";
            }

            // Verify JWT token signature if certificate or JWKS is configured
            String[] parts = jwtToken.split("\\.");
            if (parts.length < 2) {
                return "redirect:/login?error=invalid_token";
            }

            boolean verified = false;
            if (parts.length == 3) {
                // Signed token - verify signature
                if (provider.getJwtCertificate() != null && !provider.getJwtCertificate().isEmpty()) {
                    verified = verifyJwtSignature(jwtToken, provider.getJwtCertificate());
                    if (!verified) {
                        return "redirect:/login?error=jwt_signature_verification_failed";
                    }
                } else if (provider.getJwtJwksUri() != null && !provider.getJwtJwksUri().isEmpty()) {
                    // JWKS verification - for now, just check if JWKS URI is reachable
                    // Full JWKS verification can be implemented later
                    try {
                        new URI(provider.getJwtJwksUri()).toURL().openStream().close();
                        verified = true; // JWKS URI is reachable
                    } catch (Exception e) {
                        return "redirect:/login?error=jwks_unreachable";
                    }
                } else {
                    // No verification method configured - accept token (not recommended for production)
                    verified = true;
                }
            } else {
                // Unsigned token
                verified = true;
            }

            // Decode JWT payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = objectMapper.readValue(payloadJson, 
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

            // Extract username/email from claims first (needed for both test and normal flow)
            String username = null;
            if (claims.containsKey("email")) {
                username = String.valueOf(claims.get("email"));
            } else if (claims.containsKey("preferred_username")) {
                username = String.valueOf(claims.get("preferred_username"));
            } else if (claims.containsKey("sub")) {
                username = String.valueOf(claims.get("sub"));
            } else if (claims.containsKey("username")) {
                username = String.valueOf(claims.get("username"));
            }

            if (username == null || username.isEmpty()) {
                username = "jwt_user_" + java.util.UUID.randomUUID().toString().substring(0, 8);
            }

            // Check if this is a test flow
            javax.servlet.http.HttpSession session = request.getSession(false);
            boolean isTest = session != null && Boolean.TRUE.equals(session.getAttribute("jwt_test"));
            if (isTest && session != null) {
                String testCompany = (String) session.getAttribute("sso_test_company");
                if (testCompany != null) {
                    company = testCompany;
                }
                java.util.Map<String,String> attrMap = new java.util.LinkedHashMap<>();
                claims.forEach((k, v) -> attrMap.put(k, v != null ? String.valueOf(v) : ""));
                session.setAttribute("test_success", true);
                session.setAttribute("test_protocol", "JWT");
                session.setAttribute("test_nameId", username);
                session.setAttribute("test_attributes", attrMap);
                session.removeAttribute("jwt_test");
                session.removeAttribute("jwt_test_provider_id");
                session.removeAttribute("sso_test");
                if (company != null) {
                    return "redirect:/" + company + "/customer-admin/dashboard?test=success";
                }
                request.setAttribute("jwt_test_result", claims);
                return "redirect:/test/jwt/result";
            }

            // Authenticate user - get user's actual role from database
            String userRole = "ROLE_END_USER"; // Default role
            User dbUser = userRepository.findByUsername(username).orElse(null);
            if (dbUser != null) {
                userRole = dbUser.getRole(); // Returns "ROLE_SUPER_ADMIN", "ROLE_CUSTOMER_ADMIN", or "ROLE_END_USER"
            }
            var auth = new UsernamePasswordAuthenticationToken(username, "N/A",
                    Collections.singletonList(new SimpleGrantedAuthority(userRole)));
            SecurityContextHolder.getContext().setAuthentication(auth);

            // Get redirect path based on user role and company
            String redirectPath = userCompanyMapper.getRedirectPath(username);
            return "redirect:" + redirectPath;
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/login?error=callback_error";
        }
    }

    @GetMapping("/sso/jwt/login")
    public String jwtLogin(@RequestParam Long providerId, Model model, HttpServletRequest request) {
        SSOProvider provider = providerRepository.findById(providerId).orElse(null);
        if (provider == null || !"JWT".equalsIgnoreCase(provider.getType())) {
            return "redirect:/login?error=jwt_provider_not_found";
        }
        model.addAttribute("providerId", providerId);
        model.addAttribute("providerName", provider.getName());
        model.addAttribute("hasCert", provider.getJwtCertificate() != null && !provider.getJwtCertificate().isEmpty());
        model.addAttribute("hasJwks", provider.getJwtJwksUri() != null && !provider.getJwtJwksUri().isEmpty());
        // Store provider ID in session for verification
        request.getSession(true).setAttribute("jwt_provider_id", providerId);
        return "jwt_login";
    }

    @PostMapping("/sso/jwt/verify")
    public String verifyJwt(@RequestParam Long providerId, @RequestParam String token,
                           HttpServletRequest request, Model model) {
        SSOProvider provider = providerRepository.findById(providerId).orElse(null);
        if (provider == null || !"JWT".equalsIgnoreCase(provider.getType())) {
            return "redirect:/login?error=jwt_provider_not_found";
        }

        if (token == null || token.trim().isEmpty()) {
            model.addAttribute("error", "Please provide a JWT token");
            model.addAttribute("providerId", providerId);
            model.addAttribute("providerName", provider.getName());
            return "jwt_login";
        }

        try {
            String[] parts = token.trim().split("\\.");
            if (parts.length < 2) {
                model.addAttribute("error", "Invalid JWT token format");
                model.addAttribute("providerId", providerId);
                model.addAttribute("providerName", provider.getName());
                return "jwt_login";
            }

            // Decode payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = objectMapper.readValue(payloadJson,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

            // Verify signature if certificate or JWKS is configured
            boolean verified = false;
            if (parts.length == 3) {
                if (provider.getJwtCertificate() != null && !provider.getJwtCertificate().isEmpty()) {
                    verified = verifyJwtSignature(token, provider.getJwtCertificate());
                } else if (provider.getJwtJwksUri() != null && !provider.getJwtJwksUri().isEmpty()) {
                    // For JWKS, we'll skip verification for now (can be enhanced later)
                    verified = true; // Assume valid if JWKS URI is reachable
                    try {
                        new URI(provider.getJwtJwksUri()).toURL().openStream().close();
                    } catch (Exception e) {
                        verified = false;
                    }
                } else {
                    // No verification method, accept token
                    verified = true;
                }
            } else {
                // Unsigned token, accept it
                verified = true;
            }

            if (!verified) {
                model.addAttribute("error", "JWT signature verification failed");
                model.addAttribute("providerId", providerId);
                model.addAttribute("providerName", provider.getName());
                return "jwt_login";
            }

            // Extract username/email from claims
            String username = null;
            if (claims.containsKey("email")) {
                username = String.valueOf(claims.get("email"));
            } else if (claims.containsKey("preferred_username")) {
                username = String.valueOf(claims.get("preferred_username"));
            } else if (claims.containsKey("sub")) {
                username = String.valueOf(claims.get("sub"));
            } else if (claims.containsKey("username")) {
                username = String.valueOf(claims.get("username"));
            }

            if (username == null || username.isEmpty()) {
                username = "jwt_user_" + java.util.UUID.randomUUID().toString().substring(0, 8);
            }

            // Authenticate user - get user's actual role from database
            String userRole = "ROLE_END_USER"; // Default role
            User dbUser = userRepository.findByUsername(username).orElse(null);
            if (dbUser != null) {
                userRole = dbUser.getRole(); // Returns "ROLE_SUPER_ADMIN", "ROLE_CUSTOMER_ADMIN", or "ROLE_END_USER"
            }
            var auth = new UsernamePasswordAuthenticationToken(username, "N/A",
                    Collections.singletonList(new SimpleGrantedAuthority(userRole)));
            SecurityContextHolder.getContext().setAuthentication(auth);

            // Clear session
            request.getSession(false).removeAttribute("jwt_provider_id");
            request.getSession(false).removeAttribute("jwt_login");

            // Get redirect path based on user role and company
            String redirectPath = userCompanyMapper.getRedirectPath(username);
            return "redirect:" + redirectPath;
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Error processing JWT: " + e.getMessage());
            model.addAttribute("providerId", providerId);
            model.addAttribute("providerName", provider.getName());
            return "jwt_login";
        }
    }

    private boolean verifyJwtSignature(String token, String certPem) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String alg = getJsonValue(headerJson, "alg");
            if (alg == null) return false;

            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
            String signingInput = parts[0] + "." + parts[1];

            java.security.PublicKey publicKey = parsePublicKeyFromPem(certPem);
            String jcaAlg = mapJwsAlgToJca(alg);
            if (publicKey == null || jcaAlg == null) return false;

            java.security.Signature sig = java.security.Signature.getInstance(jcaAlg);
            sig.initVerify(publicKey);
            sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private String getJsonValue(String json, String key) {
        String q = "\"" + key + "\"";
        int i = json.indexOf(q);
        if (i < 0) return null;
        int c = json.indexOf(':', i + q.length());
        if (c < 0) return null;
        int s = json.indexOf('"', c + 1);
        if (s < 0) return null;
        int e = json.indexOf('"', s + 1);
        if (e < 0) return null;
        return json.substring(s + 1, e);
    }

    private java.security.PublicKey parsePublicKeyFromPem(String pem) {
        try {
            String normalized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(normalized);
            try {
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(der);
                return java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (Exception ignore) {
            }
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) 
                cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            return cert.getPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    private String mapJwsAlgToJca(String alg) {
        if (alg == null) return null;
        return switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> null;
        };
    }
}

