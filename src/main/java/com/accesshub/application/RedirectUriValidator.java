package com.accesshub.application;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

@Component
public class RedirectUriValidator {

    public void validateRedirectUris(String redirectUris) {
        if (redirectUris == null || redirectUris.isBlank()) {
            return;
        }

        List<String> uris = Arrays.stream(redirectUris.split("[,\\s]+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();

        for (String uriStr : uris) {
            validateSingleUri(uriStr);
        }
    }

    public void validateSingleUri(String uriStr) {
        if (uriStr == null || uriStr.isBlank()) {
            throw new IllegalArgumentException("Redirect URI cannot be empty");
        }

        if (uriStr.contains("*")) {
            throw new IllegalArgumentException("Wildcard patterns are forbidden in redirect URIs to prevent open redirect vulnerabilities: " + uriStr);
        }

        URI uri;
        try {
            uri = new URI(uriStr);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Malformed redirect URI: " + uriStr, e);
        }

        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("Redirect URI must specify a scheme: " + uriStr);
        }

        String host = uri.getHost();
        if (host == null) {
            throw new IllegalArgumentException("Redirect URI must specify a valid host: " + uriStr);
        }

        boolean isLocalhost = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        if ("http".equalsIgnoreCase(scheme)) {
            if (!isLocalhost) {
                throw new IllegalArgumentException("Plain HTTP redirect URIs are strictly forbidden except for localhost development: " + uriStr);
            }
        } else if (!"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("Only HTTPS scheme is allowed for redirect URIs: " + uriStr);
        }

        if (uri.getFragment() != null) {
            throw new IllegalArgumentException("Redirect URI must not contain URL fragments (#): " + uriStr);
        }

        if (uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Redirect URI must not contain credentials (user:pass): " + uriStr);
        }
    }
}
