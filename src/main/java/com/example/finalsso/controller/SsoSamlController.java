package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.User;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.repository.SSOProviderRepository;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.entity.SSOProvider;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@Controller
public class SsoSamlController {

    private final SSOConfigService cfgService;
    private final SSOProviderRepository providerRepository;
    private final UserRepository userRepository;

    public SsoSamlController(SSOConfigService cfgService, SSOProviderRepository providerRepository, UserRepository userRepository) {
        this.cfgService = cfgService;
        this.providerRepository = providerRepository;
        this.userRepository = userRepository;
    }

	@GetMapping("/sso/saml2/authenticate")
	public String authenticate(@RequestParam(required = false) Long providerId, HttpServletRequest request) throws Exception {
        SSOConfig cfg = cfgService.get();

		String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
		String acsUrl = baseUrl + "/sso/saml2/acs";
		String spEntityId = baseUrl;
        // Prefer selected test provider, then providerId param, otherwise an active SAML provider if available
        String idpEntityId;
        String idpSsoUrl;
        Long testProviderId = (Long) request.getSession(true).getAttribute("saml_test_provider_id");
        SSOProvider activeSaml = null;
        if (testProviderId != null) {
            activeSaml = providerRepository.findById(testProviderId).orElse(null);
        }
        if (activeSaml == null && providerId != null) {
            activeSaml = providerRepository.findById(providerId).orElse(null);
        }
        if (activeSaml == null) {
            activeSaml = providerRepository.findAll().stream()
                .filter(p -> p.isActive() && "SAML".equalsIgnoreCase(p.getType()))
                .findFirst().orElse(null);
        }
        if (activeSaml != null) {
            idpEntityId = activeSaml.getSamlEntityId();
            idpSsoUrl = activeSaml.getSamlSsoUrl();
        } else {
            if (!"SAML".equalsIgnoreCase(cfg.getActiveProtocol())) {
                return "redirect:/login/sso";
            }
            idpEntityId = cfg.getSamlEntityId();
            idpSsoUrl = cfg.getSamlSsoUrl();
        }

		String requestId = "_" + UUID.randomUUID().toString().replace("-", "");
		HttpSession session = request.getSession(true);
        session.setAttribute("saml_request_id", requestId);

		// Generate SAML AuthnRequest
		String authnRequest = String.format(
			"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"ID=\"%s\" " +
			"Version=\"2.0\" " +
			"IssueInstant=\"%s\" " +
			"Destination=\"%s\" " +
			"AssertionConsumerServiceURL=\"%s\">" +
			"<saml:Issuer>%s</saml:Issuer>" +
			"<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\"/>" +
			"</samlp:AuthnRequest>",
			requestId,
			java.time.Instant.now().toString(),
			idpSsoUrl,
			acsUrl,
			spEntityId
		);

		// Deflate and Base64 encode
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, new Deflater(Deflater.DEFLATED, true))) {
			dos.write(authnRequest.getBytes(StandardCharsets.UTF_8));
		}
		String encoded = Base64.getEncoder().encodeToString(baos.toByteArray());

		// Redirect to IdP
        String relay = requestId;
        if (Boolean.TRUE.equals(session.getAttribute("saml_test"))) {
            relay = "TEST::" + requestId;
        }
        String redirectUrl = idpSsoUrl + (idpSsoUrl.contains("?") ? "&" : "?") + "SAMLRequest=" +
                java.net.URLEncoder.encode(encoded, StandardCharsets.UTF_8) +
                "&RelayState=" + java.net.URLEncoder.encode(relay, StandardCharsets.UTF_8);

		return "redirect:" + redirectUrl;
	}

	@PostMapping("/sso/saml2/acs")
	public String acs(@RequestParam(required = false) String SAMLResponse,
			@RequestParam(required = false) String RelayState,
			HttpServletRequest request) {
        try {
			if (SAMLResponse == null || SAMLResponse.isEmpty()) {
				return "redirect:/login?error";
			}

			// Decode SAMLResponse
			byte[] decoded = Base64.getDecoder().decode(SAMLResponse);
			String xml = new String(decoded, StandardCharsets.UTF_8);

			// Parse XML to extract user attributes
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			Document doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

            // Extract NameID or email
			String username = null;
			NodeList nameIdList = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
			if (nameIdList.getLength() > 0) {
				username = nameIdList.item(0).getTextContent();
			}
			if (username == null || username.isEmpty()) {
				NodeList attrs = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
				for (int i = 0; i < attrs.getLength(); i++) {
					Element attr = (Element) attrs.item(i);
					String name = attr.getAttribute("Name");
					if (name != null && (name.contains("email") || name.contains("Email") || name.equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))) {
						NodeList values = attr.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
						if (values.getLength() > 0) {
							username = values.item(0).getTextContent();
							break;
						}
					}
				}
			}
			if (username == null || username.isEmpty()) {
				username = "saml_user_" + UUID.randomUUID().toString().substring(0, 8);
			}

            // If test flow, render result with attributes instead of authenticating
            HttpSession session = request.getSession(false);
            boolean isTest = session != null && Boolean.TRUE.equals(session.getAttribute("saml_test"));
            if (isTest) {
                request.setAttribute("testSuccess", true);
                request.setAttribute("testProtocol", "SAML");
                request.setAttribute("nameId", username);
                // Simple attribute listing (name -> first value)
                java.util.Map<String,String> attrMap = new java.util.LinkedHashMap<>();
                NodeList attrs = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
                for (int i = 0; i < attrs.getLength(); i++) {
                    Element attr = (Element) attrs.item(i);
                    String name = attr.getAttribute("Name");
                    NodeList values = attr.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
                    if (values.getLength() > 0) {
                        attrMap.put(name, values.item(0).getTextContent());
                    }
                }
                request.setAttribute("attributes", attrMap);
                // clear flags
                session.removeAttribute("saml_test");
                session.removeAttribute("saml_test_provider_id");
                return "test_sso_result";
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

			return "redirect:/user/dashboard";
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
	}
}

