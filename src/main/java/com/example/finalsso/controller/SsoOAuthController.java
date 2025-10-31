package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOConfig;
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
	private final RestTemplate restTemplate = new RestTemplate();

	public SsoOAuthController(SSOConfigService cfgService) { this.cfgService = cfgService; }

	@GetMapping("/sso/oauth2/authorize")
	public String authorize(HttpServletRequest request) {
		try {
			SSOConfig cfg = cfgService.get();
			if (!"OIDC".equalsIgnoreCase(cfg.getActiveProtocol())) {
				return "redirect:/login/sso";
			}
			String clientId = cfg.getOidcClientId();
			if (clientId == null || clientId.isEmpty()) {
				return "redirect:/login?error=config";
			}
			String scopes = cfg.getOidcScopes() != null ? cfg.getOidcScopes() : "openid,profile,email";
			String authz = cfg.getOidcAuthorizationEndpoint();
			if (authz == null || authz.isEmpty()) {
				authz = cfg.getOidcIssuerUri();
			}
			if (authz == null || authz.isEmpty()) {
				return "redirect:/login?error=config";
			}
			String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
			String redirectUri = cfg.getOidcRedirectUri();
			if (redirectUri == null || redirectUri.isEmpty()) {
				redirectUri = baseUrl + "/sso/oauth2/callback";
			}
			String state = UUID.randomUUID().toString();
			request.getSession(true).setAttribute("oauth_state", state);
			String url = authz
					+ (authz.contains("?") ? "&" : "?")
					+ "response_type=code"
					+ "&client_id=" + url(clientId)
					+ "&redirect_uri=" + url(redirectUri)
					+ "&scope=" + url(scopes.replace(" ", ","))
					+ "&state=" + url(state);
			return "redirect:" + url;
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
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
			SSOConfig cfg = cfgService.get();
			String redirectUri = cfg.getOidcRedirectUri();
			if (redirectUri == null || redirectUri.isEmpty()) {
				String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
				redirectUri = baseUrl + "/sso/oauth2/callback";
			}

			// Exchange code for token
			String tokenEndpoint = cfg.getOidcTokenEndpoint();
			if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
				tokenEndpoint = cfg.getOidcIssuerUri();
				if (tokenEndpoint != null && !tokenEndpoint.isEmpty() && !tokenEndpoint.endsWith("/token")) {
					tokenEndpoint = tokenEndpoint + (tokenEndpoint.endsWith("/") ? "" : "/") + "token";
				}
			}
			if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
				return "redirect:/login?error=config";
			}

			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
			form.add("grant_type", "authorization_code");
			form.add("code", code);
			form.add("redirect_uri", redirectUri);
			form.add("client_id", cfg.getOidcClientId());
			form.add("client_secret", cfg.getOidcClientSecret());
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

			// Fetch userinfo
			String userInfoUrl = cfg.getOidcUserInfoEndpoint();
			if (userInfoUrl == null || userInfoUrl.isEmpty()) {
				String issuer = cfg.getOidcIssuerUri();
				if (issuer != null && !issuer.isEmpty()) {
					userInfoUrl = issuer + (issuer.endsWith("/") ? "" : "/") + "userinfo";
				}
			}
			if (userInfoUrl == null || userInfoUrl.isEmpty()) {
				return "redirect:/login?error=config";
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
