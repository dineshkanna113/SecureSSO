package com.example.finalsso.controller.api;

import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.repository.SSOProviderRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/api/sso/providers")
public class SSOProviderController {

    private final SSOProviderRepository repo;

    public SSOProviderController(SSOProviderRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public List<SSOProvider> list() { return repo.findAll(); }

    @GetMapping("/{id}")
    public ResponseEntity<SSOProvider> get(@PathVariable Long id) {
        return repo.findById(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody SSOProvider p) {
        if (p.getName() == null || p.getName().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Provider name is required"));
        }
        if (repo.existsByNameIgnoreCase(p.getName().trim())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Provider name must be unique"));
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(repo.save(p));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @RequestBody SSOProvider p) {
        return repo.findById(id).map(existing -> {
            String newName = p.getName() != null ? p.getName().trim() : null;
            if (newName == null || newName.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Provider name is required"));
            }
            repo.findByNameIgnoreCase(newName).ifPresent(clash -> {
                if (!clash.getId().equals(id)) throw new RuntimeException("DUP");
            });
            existing.setName(newName);
            existing.setType(p.getType());
            // OIDC
            existing.setOidcClientId(p.getOidcClientId());
            existing.setOidcClientSecret(p.getOidcClientSecret());
            existing.setOidcIssuerUri(p.getOidcIssuerUri());
            existing.setOidcRedirectUri(p.getOidcRedirectUri());
            existing.setOidcScopes(p.getOidcScopes());
            existing.setOidcAuthorizationEndpoint(p.getOidcAuthorizationEndpoint());
            existing.setOidcTokenEndpoint(p.getOidcTokenEndpoint());
            existing.setOidcUserInfoEndpoint(p.getOidcUserInfoEndpoint());
            existing.setOidcLogoutEndpoint(p.getOidcLogoutEndpoint());
            // SAML
            existing.setSamlEntityId(p.getSamlEntityId());
            existing.setSamlSsoUrl(p.getSamlSsoUrl());
            existing.setSamlX509Cert(p.getSamlX509Cert());
            existing.setSamlMetadataXml(p.getSamlMetadataXml());
            existing.setSamlMetadataUrl(p.getSamlMetadataUrl());
            // JWT
            existing.setJwtIssuer(p.getJwtIssuer());
            existing.setJwtAudience(p.getJwtAudience());
            existing.setJwtJwksUri(p.getJwtJwksUri());
            existing.setJwtHeaderName(p.getJwtHeaderName());
            existing.setJwtCertificate(p.getJwtCertificate());
            existing.setJwtSsoUrl(p.getJwtSsoUrl());
            existing.setJwtClientId(p.getJwtClientId());
            existing.setJwtClientSecret(p.getJwtClientSecret());
            existing.setJwtRedirectUri(p.getJwtRedirectUri());
            try {
                return ResponseEntity.ok(repo.save(existing));
            } catch (RuntimeException ex) {
                if ("DUP".equals(ex.getMessage())) {
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Provider name must be unique"));
                }
                throw ex;
            }
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        if (!repo.existsById(id)) return ResponseEntity.notFound().build();
        repo.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/activate")
    public ResponseEntity<?> activate(@PathVariable Long id) {
        return repo.findById(id).map(p -> {
            p.setActive(true);
            repo.save(p);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/deactivate")
    public ResponseEntity<?> deactivate(@PathVariable Long id) {
        return repo.findById(id).map(p -> {
            p.setActive(false);
            repo.save(p);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/active")
    public List<Long> getActive() {
        List<Long> ids = new ArrayList<>();
        for (var p : repo.findAll()) {
            if (p.isActive()) ids.add(p.getId());
        }
        return ids;
    }

    @GetMapping("/check-name")
    public ResponseEntity<?> checkName(@RequestParam String name, @RequestParam(required = false) Long excludeId) {
        String n = name == null ? "" : name.trim();
        if (n.isEmpty()) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Name required"));
        var opt = repo.findByNameIgnoreCase(n);
        if (opt.isPresent() && (excludeId == null || !opt.get().getId().equals(excludeId))) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Provider name already exists"));
        }
        return ResponseEntity.ok(Map.of("ok", true));
    }

    @PostMapping(value = "/metadata/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> uploadMetadata(@RequestPart("file") MultipartFile file) throws Exception {
        try (InputStream in = file.getInputStream()) {
            return parseSamlMetadata(in);
        }
    }

    @PostMapping(value = "/jwt/upload-cert", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> uploadJwtCert(@RequestPart("file") MultipartFile file) throws Exception {
        String pem = new String(file.getBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
        // Minimal normalization
        var map = new HashMap<String,Object>();
        map.put("jwtCertificate", pem);
        return map;
    }

    @GetMapping("/metadata/fetch")
    public Map<String, Object> fetchMetadata(@RequestParam String url) throws Exception {
        try (InputStream in = new URL(url).openStream()) {
            return parseSamlMetadata(in);
        }
    }

    @GetMapping("/oidc/discovery")
    public Map<String, Object> fetchOidcDiscovery(@RequestParam String url) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream in = new URL(url).openStream()) {
            Map<String, Object> config = mapper.readValue(new InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8), 
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
            
            Map<String, Object> result = new HashMap<>();
            
            // Extract issuer
            if (config.containsKey("issuer")) {
                result.put("oidcIssuerUri", config.get("issuer"));
            }
            
            // Extract authorization endpoint
            if (config.containsKey("authorization_endpoint")) {
                result.put("oidcAuthorizationEndpoint", config.get("authorization_endpoint"));
            }
            
            // Extract token endpoint
            if (config.containsKey("token_endpoint")) {
                result.put("oidcTokenEndpoint", config.get("token_endpoint"));
            }
            
            // Extract userinfo endpoint
            if (config.containsKey("userinfo_endpoint")) {
                result.put("oidcUserInfoEndpoint", config.get("userinfo_endpoint"));
            }
            
            // Extract logout endpoint
            if (config.containsKey("end_session_endpoint")) {
                result.put("oidcLogoutEndpoint", config.get("end_session_endpoint"));
            }
            
            // Extract supported scopes (use first few common ones if available)
            if (config.containsKey("scopes_supported")) {
                @SuppressWarnings("unchecked")
                List<String> scopes = (List<String>) config.get("scopes_supported");
                if (scopes != null && !scopes.isEmpty()) {
                    // Build scope string with common OIDC scopes
                    StringBuilder scopeStr = new StringBuilder();
                    for (String scope : scopes) {
                        if (scope.equals("openid") || scope.equals("profile") || scope.equals("email")) {
                            if (scopeStr.length() > 0) scopeStr.append(" ");
                            scopeStr.append(scope);
                        }
                    }
                    if (scopeStr.length() > 0) {
                        result.put("oidcScopes", scopeStr.toString());
                    } else {
                        result.put("oidcScopes", "openid profile email");
                    }
                }
            } else {
                result.put("oidcScopes", "openid profile email");
            }
            
            return result;
        }
    }

    private Map<String,Object> parseSamlMetadata(InputStream in) throws Exception {
        var doc = DocumentBuilderFactory.newInstance();
        doc.setNamespaceAware(true);
        var builder = doc.newDocumentBuilder();
        var xml = builder.parse(in);
        var map = new HashMap<String,Object>();
        var entityId = xml.getDocumentElement().getAttribute("entityID");
        map.put("samlEntityId", entityId);
        var nl = xml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "SingleSignOnService");
        if (nl.getLength() > 0) {
            var node = nl.item(0);
            var loc = node.getAttributes().getNamedItem("Location");
            if (loc != null) map.put("samlSsoUrl", loc.getNodeValue());
        }
        var certNodes = xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if (certNodes.getLength() > 0) {
            map.put("samlX509Cert", certNodes.item(0).getTextContent().trim());
        }
        return map;
    }

    @GetMapping("/{id}/test")
    public ResponseEntity<?> testProvider(@PathVariable Long id) {
        return repo.findById(id).map(p -> {
            if ("OIDC".equalsIgnoreCase(p.getType())) {
                String url = "/test/sso/oidc?providerId=" + p.getId();
                return ResponseEntity.ok(Map.of("type", "OIDC", "startUrl", url));
            } else if ("SAML".equalsIgnoreCase(p.getType())) {
                String url = "/test/sso/saml?providerId=" + p.getId();
                return ResponseEntity.ok(Map.of("type", "SAML", "startUrl", url));
            } else { // JWT
                // Check if JWT SSO URL is configured (miniOrange style)
                if (p.getJwtSsoUrl() != null && !p.getJwtSsoUrl().isBlank()) {
                    String url = "/test/sso/jwt?providerId=" + p.getId();
                    return ResponseEntity.ok(Map.of("type", "JWT", "startUrl", url, "flow", "sso"));
                }
                // Otherwise check JWKS or certificate
                boolean ok = false;
                try {
                    if (p.getJwtJwksUri() != null && !p.getJwtJwksUri().isBlank()) {
                        try (var in = new URI(p.getJwtJwksUri()).toURL().openStream()) {
                            in.readNBytes(1);
                            ok = true;
                        }
                    }
                } catch (Exception ignored) {}
                boolean certOk = p.getJwtCertificate() != null && !p.getJwtCertificate().isBlank();
                String url = "/test/sso/jwt/manual?providerId=" + p.getId();
                return ResponseEntity.ok(Map.of("type", "JWT", "jwksOk", ok, "certOk", certOk, "flow", "verify", "startUrl", url));
            }
        }).orElse(ResponseEntity.notFound().build());
    }

    private String encode(String s) {
        try {
            return java.net.URLEncoder.encode(s == null ? "" : s, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return "";
        }
    }
}


