package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.repository.SSOProviderRepository;
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
	private final RestTemplate restTemplate = new RestTemplate();

	public SsoOAuthController(SSOConfigService cfgService, SSOProviderRepository providerRepository) {
		this.cfgService = cfgService;
		this.providerRepository = providerRepository;
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
		String redirectUri = provider.getOidcRedirectUri();
		if (redirectUri == null || redirectUri.trim().isEmpty()) {
			redirectUri = baseUrl + "/sso/oauth2/callback";
		} else {
			redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
		}
		
		String state = UUID.randomUUID().toString();
		HttpSession session = request.getSession(true);
		session.setAttribute("oauth_state", state);
		if (finalProviderId != null) {
			session.setAttribute("oidc_provider_id", finalProviderId);
		}
		
		String url = authz
				+ (authz.contains("?") ? "&" : "?")
				+ "response_type=code"
				+ "&client_id=" + url(clientId)
				+ "&redirect_uri=" + url(redirectUri)
				+ "&scope=" + url(scopes.replace(",", " ").replaceAll("\\s+", " "))
				+ "&state=" + url(state);
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
		String redirectUri = cfg.getOidcRedirectUri();
		if (redirectUri == null || redirectUri.trim().isEmpty()) {
			redirectUri = baseUrl + "/sso/oauth2/callback";
		} else {
			redirectUri = redirectUri.trim(); // Remove leading/trailing spaces
		}
		String state = UUID.randomUUID().toString();
		request.getSession(true).setAttribute("oauth_state", state);
		String url = authz
				+ (authz.contains("?") ? "&" : "?")
				+ "response_type=code"
				+ "&client_id=" + url(clientId)
				+ "&redirect_uri=" + url(redirectUri)
				+ "&scope=" + url(scopes.replace(",", " ").replaceAll("\\s+", " "))
				+ "&state=" + url(state);
		return "redirect:" + url;
	}

	@GetMapping("/sso/oauth2/callback")
	public String callback(@RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
			@RequestParam(required = false) String error,
			HttpServletRequest request,
			Model model) {
		try {
			if (error != null) {
				return "redirect:/login?error=" + error;
			}
			HttpSession session = request.getSession(false);
			String expected = session != null ? (String) session.getAttribute("oauth_state") : null;
			if (expected == null || state == null || !expected.equals(state) || code == null) {
				return "redirect:/login?error=invalid";
			}
			
			// Get provider from session if available
			Long providerId = null;
			if (session != null) {
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
				if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
					tokenEndpoint = provider.getOidcIssuerUri();
					if (tokenEndpoint != null && !tokenEndpoint.isEmpty() && !tokenEndpoint.endsWith("/token")) {
						tokenEndpoint = tokenEndpoint + (tokenEndpoint.endsWith("/") ? "" : "/") + "token";
					}
				}
				if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
					return "redirect:/login?error=oidc_token_endpoint_missing";
				}
				
				clientId = provider.getOidcClientId();
				clientSecret = provider.getOidcClientSecret();
				
				userInfoUrl = provider.getOidcUserInfoEndpoint();
				if (userInfoUrl == null || userInfoUrl.isEmpty()) {
					String issuer = provider.getOidcIssuerUri();
					if (issuer != null && !issuer.isEmpty()) {
						userInfoUrl = issuer + (issuer.endsWith("/") ? "" : "/") + "userinfo";
					}
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

			// Authenticate in Spring Security context
			var auth = new UsernamePasswordAuthenticationToken(username, "N/A", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
			SecurityContextHolder.getContext().setAuthentication(auth);
			return "redirect:/user/dashboard";
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
	}

	private static String url(String v){ return URLEncoder.encode(v, StandardCharsets.UTF_8); }
}
