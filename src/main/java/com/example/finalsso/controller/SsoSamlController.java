package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.User;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.service.UserCompanyMapper;
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
    private final UserCompanyMapper userCompanyMapper;

    public SsoSamlController(SSOConfigService cfgService, SSOProviderRepository providerRepository, UserRepository userRepository, UserCompanyMapper userCompanyMapper) {
        this.cfgService = cfgService;
        this.providerRepository = providerRepository;
        this.userRepository = userRepository;
        this.userCompanyMapper = userCompanyMapper;
    }

	@GetMapping("/sso/saml2/authenticate")
	public String authenticate(@RequestParam(required = false) Long providerId, HttpServletRequest request) throws Exception {
        SSOConfig cfg = cfgService.get();

		String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
		// Check if we have tenant context from test or provider
		HttpSession session = request.getSession(false);
		String company = session != null ? (String) session.getAttribute("sso_test_company") : null;
		// If company not in session, try to get from provider's tenant
		if (company == null) {
			// Try to get from provider if available
			Long testProviderId = (Long) (session != null ? session.getAttribute("saml_test_provider_id") : null);
			if (testProviderId != null) {
				SSOProvider testProvider = providerRepository.findById(testProviderId).orElse(null);
				if (testProvider != null && testProvider.getTenant() != null) {
					company = testProvider.getTenant().getTenantName();
					if (company != null) {
						company = company.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-+", "").replaceAll("-+$", "");
					}
				}
			}
		}
		String spEntityId = baseUrl;
		String acsUrl = baseUrl + "/sso/saml2/acs";
		// If tenant-specific, include company in entity ID and ACS URL
		if (company != null) {
			spEntityId = baseUrl + "/" + company;
			acsUrl = baseUrl + "/" + company + "/sso/saml2/acs";
		}
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
		HttpSession session2 = request.getSession(true);
        session2.setAttribute("saml_request_id", requestId);

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
        if (session != null && Boolean.TRUE.equals(session.getAttribute("saml_test"))) {
            relay = "TEST::" + requestId;
        }
        String redirectUrl = idpSsoUrl + (idpSsoUrl.contains("?") ? "&" : "?") + "SAMLRequest=" +
                java.net.URLEncoder.encode(encoded, StandardCharsets.UTF_8) +
                "&RelayState=" + java.net.URLEncoder.encode(relay, StandardCharsets.UTF_8);

		return "redirect:" + redirectUrl;
	}

	@PostMapping({"/sso/saml2/acs", "/{company}/sso/saml2/acs"})
	public String acs(@org.springframework.web.bind.annotation.PathVariable(required = false) String company,
			@RequestParam(required = false) String SAMLResponse,
			@RequestParam(required = false) String RelayState,
			HttpServletRequest request) {
		// Extract company from path if not already set
		String extractedCompany = company;
		if (extractedCompany == null) {
			String path = request.getRequestURI();
			if (path.contains("/sso/saml2/acs")) {
				String[] parts = path.split("/");
				for (int i = 0; i < parts.length; i++) {
					if (parts[i].equals("sso") && i > 0) {
						extractedCompany = parts[i - 1];
						break;
					}
				}
			}
		}
		company = extractedCompany;
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

            // If test flow, redirect back to company admin dashboard with test data in session
            HttpSession session = request.getSession(false);
            boolean isTest = session != null && Boolean.TRUE.equals(session.getAttribute("saml_test"));
            if (isTest && session != null) {
                String testCompany = (String) session.getAttribute("sso_test_company");
                if (testCompany != null) {
                    company = testCompany;
                }
                // Store test result in session for modal display
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
                session.setAttribute("test_success", true);
                session.setAttribute("test_protocol", "SAML");
                session.setAttribute("test_nameId", username);
                session.setAttribute("test_attributes", attrMap);
                // clear test flags
                session.removeAttribute("saml_test");
                session.removeAttribute("saml_test_provider_id");
                session.removeAttribute("sso_test");
                if (company != null) {
                    return "redirect:/" + company + "/customer-admin/dashboard?test=success";
                }
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

			// Get redirect path based on user role and company
			String redirectPath = userCompanyMapper.getRedirectPath(username);
			return "redirect:" + redirectPath;
		} catch (Exception e) {
			e.printStackTrace();
			return "redirect:/login?error";
		}
	}
}

