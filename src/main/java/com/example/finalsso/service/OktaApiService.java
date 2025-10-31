package com.example.finalsso.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class OktaApiService {

    private final OktaApiTokenService tokenService;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${okta.api.base-url}")
    private String baseUrl;

    public OktaApiService(OktaApiTokenService tokenService) {
        this.tokenService = tokenService;
    }

    public String listUsers() {
        String accessToken = tokenService.getAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                baseUrl + "/users",
                HttpMethod.GET,
                entity,
                String.class
        );

        return response.getBody();
    }
}
