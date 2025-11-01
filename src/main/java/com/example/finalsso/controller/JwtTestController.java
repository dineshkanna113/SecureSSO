package com.example.finalsso.controller;

import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.repository.SSOProviderRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Controller
public class JwtTestController {

    private final SSOProviderRepository repo;

    public JwtTestController(SSOProviderRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/test/sso/jwt/manual")
    public String testJwt(@RequestParam Long providerId, Model model) {
        SSOProvider p = repo.findById(providerId).orElse(null);
        if (p == null || !"JWT".equalsIgnoreCase(p.getType())) {
            model.addAttribute("error", "JWT provider not found");
            return "test_jwt";
        }
        model.addAttribute("providerId", providerId);
        model.addAttribute("hasCert", p.getJwtCertificate() != null && !p.getJwtCertificate().isBlank());
        model.addAttribute("hasJwks", p.getJwtJwksUri() != null && !p.getJwtJwksUri().isBlank());
        return "test_jwt";
    }

    @PostMapping("/test/sso/jwt/verify")
    public String verifyJwt(@RequestParam Long providerId, @RequestParam String token, Model model) {
        SSOProvider p = repo.findById(providerId).orElse(null);
        model.addAttribute("providerId", providerId);
        if (token == null || token.isBlank()) {
            model.addAttribute("error", "Please paste a JWT token");
            return "test_jwt";
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) throw new IllegalArgumentException("Invalid JWT");
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            model.addAttribute("header", headerJson);
            model.addAttribute("claims", payloadJson);

            boolean verified = false;
            String alg = getJsonValue(headerJson, "alg");
            if (p != null && p.getJwtCertificate() != null && !p.getJwtCertificate().isBlank() && parts.length == 3) {
                String sigB64 = parts[2];
                byte[] signature = Base64.getUrlDecoder().decode(sigB64);
                String signingInput = parts[0] + "." + parts[1];
                String certPem = p.getJwtCertificate();
                PublicKey publicKey = parsePublicKeyFromPem(certPem);
                String jcaAlg = mapJwsAlgToJca(alg);
                if (publicKey != null && jcaAlg != null) {
                    Signature sig = Signature.getInstance(jcaAlg);
                    sig.initVerify(publicKey);
                    sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
                    verified = sig.verify(signature);
                }
            }
            model.addAttribute("verified", verified);
            model.addAttribute("success", true);
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
        }
        return "test_jwt";
    }

    private static String getJsonValue(String json, String key) {
        // very small JSON value extractor for flat keys (not robust, but fine for alg)
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

    private static PublicKey parsePublicKeyFromPem(String pem) {
        try {
            String normalized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(normalized);
            try {
                // Try X509EncodedKeySpec first (PUBLIC KEY or cert subjectPublicKeyInfo)
                X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (Exception ignore) {
            }
            // Try parsing full certificate and extract key
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            return cert.getPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    private static String mapJwsAlgToJca(String alg) {
        if (alg == null) return null;
        return switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> null;
        };
    }
}




