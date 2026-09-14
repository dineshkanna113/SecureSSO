package com.accesshub.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = getJwtFromRequest(request);
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                Claims claims = tokenProvider.getClaims(jwt);

                // Ensure token is an ACCESS token
                String tokenType = claims.get("type", String.class);
                if ("REFRESH".equals(tokenType)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                UUID userId = UUID.fromString(claims.getSubject());
                UUID tenantId = UUID.fromString(claims.get("tenantId", String.class));
                String email = claims.get("email", String.class);

                List<?> authList = claims.get("authorities", List.class);
                Set<SimpleGrantedAuthority> authorities = authList != null ?
                        authList.stream().map(a -> new SimpleGrantedAuthority(a.toString())).collect(Collectors.toSet())
                        : Collections.emptySet();

                List<?> rolesList = claims.get("roles", List.class);
                Set<String> roles = rolesList != null ?
                        rolesList.stream().map(Object::toString).collect(Collectors.toSet())
                        : Collections.emptySet();

                UserPrincipal principal = UserPrincipal.builder()
                        .userId(userId)
                        .tenantId(tenantId)
                        .email(email)
                        .authorities(authorities)
                        .roles(roles)
                        .enabled(true)
                        .locked(false)
                        .build();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.error("Could not set user authentication in security context", e);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
