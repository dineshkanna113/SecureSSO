package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.entity.User;
import com.example.finalsso.service.UserCompanyMapper;
import com.example.finalsso.repository.SSOProviderRepository;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.service.SSOConfigService;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.ParameterizedTypeReference;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@Controller
public class SsoOAuthController {

	private final SSOConfigService cfgService;
	private final SSOProviderRepository providerRepository;
	private final UserRepository userRepository;
	private final UserCompanyMapper userCompanyMapper;
	private final RestTemplate restTemplate = new RestTemplate();

	public SsoOAuthController(SSOConfigService cfgService, SSOProviderRepository providerRepository, UserRepository userRepository, UserCompanyMapper userCompanyMapper) {
		this.cfgService = cfgService;
		this.providerRepository = providerRepository;
		this.userRepository = userRepository;
		this.userCompanyMapper = userCompanyMapper;
	}

	@GetMapping("/sso/oauth2/authorize")
	public String authorize(@RequestParam(required = false) Long providerId, HttpServletRequest request) {
		try {
			SSOProvider provider = null;
			// Check for test provider ID from session
			Long testProviderId = null;
			var session = request.getSession(false);
			if (session != null) {
				Object attr = session.getAttribute("oidc_test_provider_id");
				if (attr instanceof Long) {
					testProviderId = (Long) attr;
				}
			}
			
			if (providerId != null) {
				provider = providerRepository.findById(providerId).orElse(null);
			} else if (testProviderId != null) {
				provider = providerRepository.findById(testProviderId).orElse(null);
			} else {
				// Find first active OIDC provider
				provider = providerRepository.findAll().stream()
						.filter(p -> p.isActive() && "OIDC".equalsIgnoreCase(p.getType()))
						.findFirst().orElse(null);
			}
			
			// Fallback to SSOConfig if no provider found
			if (provider == null) {
				SSOConfig cfg = cfgService.get();
				if (!"OIDC".equalsIgnoreCase(cfg.getActiveProtocol())) {
					return "redirect:/login/sso";
				}
				return authorizeWithConfig(cfg, null, request);
			}
			
			// Use provider-specific configuration
			return authorizeWithProvider(provider, providerId != null ? providerId : (testProviderId != null ? testProviderId : provider.getId()), request);
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
	}
	
	private String authorizeWithProvider(SSOProvider provider, Long finalProviderId, HttpServletRequest request) {
		String clientId = provider.getOidcClientId();
		if (clientId == null || clientId.isEmpty()) {
			return "redirect:/login?error=oidc_client_id_missing";
		}
		
		String scopes = provider.getOidcScopes() != null && !provider.getOidcScopes().trim().isEmpty() 
				? provider.getOidcScopes().trim() : "openid profile email";
		String authz = provider.getOidcAuthorizationEndpoint();
		if (authz == null || authz.isEmpty()) {
			authz = provider.getOidcIssuerUri();
		}
		if (authz == null || authz.isEmpty()) {
			return "redirect:/login?error=oidc_authorization_endpoint_missing";
		}
		
		String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
		// Remove trailing slash from baseUrl if present
		if (baseUrl.endsWith("/")) {
			baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
		}
		
		// Extract company from session or provider's tenant
		String company = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			company = (String) session.getAttribute("sso_test_company");
		}
		if (company == null && provider.getTenant() != null) {
			company = provider.getTenant().getTenantName();
			if (company != null) {
				company = company.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-+", "").replaceAll("-+$", "");
			}
		}
		
		// Build company-specific redirect URI
		String redirectUri = provider.getOidcRedirectUri();
		if (redirectUri == null || redirectUri.trim().isEmpty()) {
			if (company != null) {
				redirectUri = baseUrl + "/" + company + "/sso/oauth2/callback";
			} else {
				redirectUri = baseUrl + "/sso/oauth2/callback";
			}
		} else {
			redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
			// If redirect URI is relative, make it absolute
			if (redirectUri.startsWith("/")) {
				redirectUri = baseUrl + redirectUri;
			}
			// Validate that redirect URI is for our application, not miniOrange
			if (redirectUri.contains("xecurify.com") || redirectUri.contains("miniorange")) {
				// Reset to company-specific default if it points to miniOrange
				if (company != null) {
					redirectUri = baseUrl + "/" + company + "/sso/oauth2/callback";
				} else {
					redirectUri = baseUrl + "/sso/oauth2/callback";
				}
			}
		}
		
		String state = UUID.randomUUID().toString();
		String nonce = UUID.randomUUID().toString();
		HttpSession session2 = request.getSession(true);
		session2.setAttribute("oauth_state", state);
		session2.setAttribute("oauth_nonce", nonce);
		if (finalProviderId != null) {
			session2.setAttribute("oidc_provider_id", finalProviderId);
		}
		if (company != null) {
			session2.setAttribute("sso_test_company", company);
		}
		
		// Ensure scope starts with "openid" for OIDC compliance
		String normalizedScopes = scopes.replace(",", " ").replaceAll("\\s+", " ").trim();
		if (!normalizedScopes.toLowerCase().startsWith("openid")) {
			if (normalizedScopes.isEmpty()) {
				normalizedScopes = "openid profile email";
			} else {
				normalizedScopes = "openid " + normalizedScopes;
			}
		}
		
		// Debug logging
		System.out.println("DEBUG OIDC Authorization URL:");
		System.out.println("  Client ID: " + clientId);
		System.out.println("  Redirect URI: " + redirectUri);
		System.out.println("  Scopes: " + normalizedScopes);
		System.out.println("  Authorization Endpoint: " + authz);
		
		// Build URL with correct parameter order for miniOrange: client_id, redirect_uri, response_type, scope, state, nonce
		String url = authz
				+ (authz.contains("?") ? "&" : "?")
				+ "client_id=" + url(clientId)
				+ "&redirect_uri=" + url(redirectUri)
				+ "&response_type=code"
				+ "&scope=" + url(normalizedScopes)
				+ "&state=" + url(state)
				+ "&nonce=" + url(nonce);
		
		System.out.println("  Full URL: " + url);
		
		return "redirect:" + url;
	}
	
	private String authorizeWithConfig(SSOConfig cfg, Long providerId, HttpServletRequest request) {
		String clientId = cfg.getOidcClientId();
		if (clientId == null || clientId.isEmpty()) {
			return "redirect:/login?error=config";
		}
		String scopes = cfg.getOidcScopes() != null && !cfg.getOidcScopes().trim().isEmpty() 
				? cfg.getOidcScopes().trim() : "openid profile email";
		String authz = cfg.getOidcAuthorizationEndpoint();
		if (authz == null || authz.isEmpty()) {
			authz = cfg.getOidcIssuerUri();
		}
		if (authz == null || authz.isEmpty()) {
			return "redirect:/login?error=config";
		}
		String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
		// Remove trailing slash from baseUrl if present
		if (baseUrl.endsWith("/")) {
			baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
		}
		
		String redirectUri = cfg.getOidcRedirectUri();
		if (redirectUri == null || redirectUri.trim().isEmpty()) {
			redirectUri = baseUrl + "/sso/oauth2/callback";
		} else {
			redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
			// If redirect URI is relative, make it absolute
			if (redirectUri.startsWith("/")) {
				redirectUri = baseUrl + redirectUri;
			}
			// Validate that redirect URI is for our application, not miniOrange
			if (redirectUri.contains("xecurify.com") || redirectUri.contains("miniorange")) {
				// Reset to default if it points to miniOrange
				redirectUri = baseUrl + "/sso/oauth2/callback";
			}
		}
		String state = UUID.randomUUID().toString();
		String nonce = UUID.randomUUID().toString();
		HttpSession session = request.getSession(true);
		session.setAttribute("oauth_state", state);
		session.setAttribute("oauth_nonce", nonce);
		
		// Ensure scope starts with "openid" for OIDC compliance
		String normalizedScopes = scopes.replace(",", " ").replaceAll("\\s+", " ").trim();
		if (!normalizedScopes.toLowerCase().startsWith("openid")) {
			if (normalizedScopes.isEmpty()) {
				normalizedScopes = "openid profile email";
			} else {
				normalizedScopes = "openid " + normalizedScopes;
			}
		}
		
		// Build URL with correct parameter order for miniOrange: client_id, redirect_uri, response_type, scope, state, nonce
		String url = authz
				+ (authz.contains("?") ? "&" : "?")
				+ "client_id=" + url(clientId)
				+ "&redirect_uri=" + url(redirectUri)
				+ "&response_type=code"
				+ "&scope=" + url(normalizedScopes)
				+ "&state=" + url(state)
				+ "&nonce=" + url(nonce);
		return "redirect:" + url;
	}

	@GetMapping({"/sso/oauth2/callback", "/{company}/sso/oauth2/callback"})
	public String callback(@org.springframework.web.bind.annotation.PathVariable(required = false) String company,
			@RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
			@RequestParam(required = false) String error,
			HttpServletRequest request,
			Model model) {
		try {
			if (error != null) {
				return "redirect:/login?error=" + error;
			}
			if (code == null) {
				return "redirect:/login?error=no_code";
			}
			
			HttpSession session = request.getSession(false);
			boolean isIdpInitiated = false;
			
			// Validate state for SP-initiated flows (state must exist and match)
			// For IdP-initiated flows, state may be null or missing
			String expected = session != null ? (String) session.getAttribute("oauth_state") : null;
			if (expected != null && state != null) {
				// SP-initiated: validate state
				if (!expected.equals(state)) {
					return "redirect:/login?error=invalid_state";
				}
			} else if (state == null && expected == null) {
				// IdP-initiated flow: no state parameter, proceed without state validation
				isIdpInitiated = true;
			} else if (state != null && expected == null) {
				// State provided but not in session - could be IdP-initiated or session expired
				isIdpInitiated = true;
			}
			
			// Get provider from session if available (SP-initiated)
			Long providerId = null;
			if (session != null && !isIdpInitiated) {
				Object attr = session.getAttribute("oidc_provider_id");
				if (attr instanceof Long) {
					providerId = (Long) attr;
				}
			}
			
			SSOProvider provider = null;
			if (providerId != null) {
				provider = providerRepository.findById(providerId).orElse(null);
				if (session != null) {
					session.removeAttribute("oidc_provider_id");
					session.removeAttribute("oauth_state");
					session.removeAttribute("oauth_nonce");
				}
			}
			
			// Extract company from path if not already set
			String extractedCompany = company;
			if (extractedCompany == null) {
				String path = request.getRequestURI();
				if (path.contains("/sso/oauth2/callback")) {
					String[] parts = path.split("/");
					for (int i = 0; i < parts.length; i++) {
						if (parts[i].equals("sso") && i > 0) {
							extractedCompany = parts[i - 1];
							break;
						}
					}
				}
			}
			final String finalCompany = extractedCompany; // Make final for lambda usage
			
			// For IdP-initiated flows, find active provider by matching redirect URI and company
			if (provider == null && isIdpInitiated) {
				String currentCallbackUrl = request.getRequestURL().toString();
				String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
				// Try to find active OIDC provider that matches this callback URL
				provider = providerRepository.findAll().stream()
					.filter(p -> p.isActive() && "OIDC".equalsIgnoreCase(p.getType()))
					.filter(p -> {
						// Match by company/tenant
						if (finalCompany != null && p.getTenant() != null) {
							String tenantSlug = p.getTenant().getTenantName();
							if (tenantSlug != null) {
								tenantSlug = tenantSlug.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-+", "").replaceAll("-+$", "");
								if (!finalCompany.equals(tenantSlug)) {
									return false;
								}
							}
						}
						String redirectUri = p.getOidcRedirectUri();
						if (redirectUri == null || redirectUri.trim().isEmpty()) {
							if (finalCompany != null) {
								redirectUri = baseUrl + "/" + finalCompany + "/sso/oauth2/callback";
							} else {
								redirectUri = baseUrl + "/sso/oauth2/callback";
							}
						} else {
							redirectUri = redirectUri.trim();
							if (redirectUri.startsWith("/")) {
								redirectUri = baseUrl + redirectUri;
							}
						}
						return currentCallbackUrl.equals(redirectUri) || 
							   currentCallbackUrl.startsWith(redirectUri.split("\\?")[0]);
					})
					.findFirst()
					.orElse(null);
				
				// If still not found, use first active OIDC provider as fallback
				if (provider == null) {
					provider = providerRepository.findAll().stream()
						.filter(p -> p.isActive() && "OIDC".equalsIgnoreCase(p.getType()))
						.findFirst()
						.orElse(null);
				}
			}
			
			String redirectUri;
			String tokenEndpoint;
			String clientId;
			String clientSecret;
			String userInfoUrl;
			
			if (provider != null) {
				// Use provider-specific configuration
			String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
			redirectUri = provider.getOidcRedirectUri();
			if (redirectUri == null || redirectUri.trim().isEmpty()) {
				redirectUri = baseUrl + "/sso/oauth2/callback";
			} else {
				redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
			}
				
				tokenEndpoint = provider.getOidcTokenEndpoint();
				// Only fallback to issuer-based construction if token endpoint is not from discovery
				if (tokenEndpoint == null || tokenEndpoint.trim().isEmpty()) {
					String issuer = provider.getOidcIssuerUri();
					if (issuer != null && !issuer.trim().isEmpty()) {
						// Try to construct from issuer (but prefer discovery endpoint)
						if (issuer.endsWith("/")) {
							tokenEndpoint = issuer + "rest/oauth/token";
						} else if (issuer.contains("/discovery/")) {
							// For miniOrange discovery URLs, use the standard token endpoint
							tokenEndpoint = issuer.replaceFirst("/discovery/[^/]+", "") + "/rest/oauth/token";
						} else {
							tokenEndpoint = issuer + (issuer.endsWith("/") ? "" : "/") + "token";
						}
					}
				} else {
					tokenEndpoint = tokenEndpoint.trim();
				}
				if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
					return "redirect:/login?error=oidc_token_endpoint_missing";
				}
				
				clientId = provider.getOidcClientId();
				clientSecret = provider.getOidcClientSecret();
				
				userInfoUrl = provider.getOidcUserInfoEndpoint();
				// Only fallback to issuer-based construction if userinfo endpoint is not from discovery
				if (userInfoUrl == null || userInfoUrl.trim().isEmpty()) {
					String issuer = provider.getOidcIssuerUri();
					if (issuer != null && !issuer.trim().isEmpty()) {
						// Try to construct from issuer (but prefer discovery endpoint)
						if (issuer.endsWith("/")) {
							userInfoUrl = issuer + "rest/oauth/getuserinfo";
						} else if (issuer.contains("/discovery/")) {
							// For miniOrange discovery URLs, use the standard userinfo endpoint
							userInfoUrl = issuer.replaceFirst("/discovery/[^/]+", "") + "/rest/oauth/getuserinfo";
						} else {
							userInfoUrl = issuer + (issuer.endsWith("/") ? "" : "/") + "userinfo";
						}
					}
				} else {
					userInfoUrl = userInfoUrl.trim();
				}
				if (userInfoUrl == null || userInfoUrl.isEmpty()) {
					return "redirect:/login?error=oidc_userinfo_endpoint_missing";
				}
			} else {
				// Fallback to SSOConfig
				SSOConfig cfg = cfgService.get();
				String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
				redirectUri = cfg.getOidcRedirectUri();
				if (redirectUri == null || redirectUri.trim().isEmpty()) {
					redirectUri = baseUrl + "/sso/oauth2/callback";
				} else {
					redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
				}
				
				tokenEndpoint = cfg.getOidcTokenEndpoint();
				if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
					tokenEndpoint = cfg.getOidcIssuerUri();
					if (tokenEndpoint != null && !tokenEndpoint.isEmpty() && !tokenEndpoint.endsWith("/token")) {
						tokenEndpoint = tokenEndpoint + (tokenEndpoint.endsWith("/") ? "" : "/") + "token";
					}
				}
				if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
					return "redirect:/login?error=config";
				}
				
				clientId = cfg.getOidcClientId();
				clientSecret = cfg.getOidcClientSecret();
				
				userInfoUrl = cfg.getOidcUserInfoEndpoint();
				if (userInfoUrl == null || userInfoUrl.isEmpty()) {
					String issuer = cfg.getOidcIssuerUri();
					if (issuer != null && !issuer.isEmpty()) {
						userInfoUrl = issuer + (issuer.endsWith("/") ? "" : "/") + "userinfo";
					}
				}
				if (userInfoUrl == null || userInfoUrl.isEmpty()) {
					return "redirect:/login?error=config";
				}
			}

			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
			form.add("grant_type", "authorization_code");
			form.add("code", code);
			form.add("redirect_uri", redirectUri);
			form.add("client_id", clientId);
			form.add("client_secret", clientSecret);
			HttpEntity<MultiValueMap<String, String>> req = new HttpEntity<>(form, headers);

			ResponseEntity<Map<String, Object>> tokenRes;
			try {
				tokenRes = restTemplate.exchange(tokenEndpoint, org.springframework.http.HttpMethod.POST, req,
						new ParameterizedTypeReference<Map<String, Object>>() {});
			} catch (Exception e) {
				e.printStackTrace();
				return "redirect:/login?error=token";
			}

			Object accessToken = tokenRes.getBody() != null ? tokenRes.getBody().get("access_token") : null;
			if (accessToken == null) {
				return "redirect:/login?error=token";
			}

			HttpHeaders uh = new HttpHeaders();
			uh.setBearerAuth(String.valueOf(accessToken));
			HttpEntity<Void> ureq = new HttpEntity<>(uh);

			ResponseEntity<Map<String, Object>> ures;
			try {
				// Try GET first (standard), fallback to POST
				ures = restTemplate.exchange(userInfoUrl, org.springframework.http.HttpMethod.GET, ureq, 
						new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});
			} catch (Exception e) {
				try {
					ures = restTemplate.exchange(userInfoUrl, org.springframework.http.HttpMethod.POST, ureq,
							new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});
				} catch (Exception e2) {
					e2.printStackTrace();
					return "redirect:/login?error=userinfo";
				}
			}

			Map<String, Object> ui = ures.getBody() != null ? ures.getBody() : Collections.emptyMap();
			String username = String.valueOf(ui.getOrDefault("email", ui.getOrDefault("preferred_username", ui.getOrDefault("sub", "user"))));

			// Check if this is a test flow
			boolean isTest = session != null && Boolean.TRUE.equals(session.getAttribute("oidc_test"));
			if (isTest && session != null) {
				String testCompany = (String) session.getAttribute("sso_test_company");
				final String testFinalCompany = testCompany != null ? testCompany : finalCompany; // Use test company or extracted company
				java.util.Map<String,String> attrMap = new java.util.LinkedHashMap<>();
				if (ui != null) {
					ui.forEach((k, v) -> attrMap.put(k, v != null ? String.valueOf(v) : ""));
				}
				session.setAttribute("test_success", true);
				session.setAttribute("test_protocol", "OIDC");
				session.setAttribute("test_nameId", username);
				session.setAttribute("test_attributes", attrMap);
				session.removeAttribute("oidc_test");
				session.removeAttribute("oidc_test_provider_id");
				session.removeAttribute("sso_test");
				if (testFinalCompany != null) {
					return "redirect:/" + testFinalCompany + "/customer-admin/dashboard?test=success";
				}
				model.addAttribute("testProtocol", "OIDC");
				model.addAttribute("nameId", username);
				model.addAttribute("attributes", ui);
				return "test_sso_result";
			}

			// Authenticate in Spring Security context - get user's actual role from database
			String userRole = "ROLE_END_USER"; // Default role
			User dbUser = userRepository.findByUsername(username).orElse(null);
			if (dbUser != null) {
				userRole = dbUser.getRole(); // Returns "ROLE_SUPER_ADMIN", "ROLE_CUSTOMER_ADMIN", or "ROLE_END_USER"
			}
			var auth = new UsernamePasswordAuthenticationToken(username, "N/A", Collections.singletonList(new SimpleGrantedAuthority(userRole)));
			SecurityContextHolder.getContext().setAuthentication(auth);
			
			// Get redirect path based on user role and company
			String redirectPath = userCompanyMapper.getRedirectPath(username);
			return "redirect:" + redirectPath;
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
	}

	private static String url(String v){ return URLEncoder.encode(v, StandardCharsets.UTF_8); }
}
