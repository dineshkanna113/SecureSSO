package com.example.finalsso.config;

import com.example.finalsso.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(u -> User.builder()
                        .username(u.getUsername())
                        .password(u.getPassword())
                        .disabled(!u.isEnabled())
                        .authorities(u.getRole())
                        .build())
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests(auth -> auth
                        .antMatchers("/register", "/css/**", "/js/**", "/images/**", "/login", "/login/sso", "/sso/oauth2/authorize", "/sso/oauth2/callback", "/sso/saml2/authenticate", "/sso/saml2/acs", "/sso/jwt/authenticate", "/sso/jwt/callback", "/sso/jwt/login", "/sso/jwt/verify", "/test/sso/jwt", "/test/sso/jwt/**", "/test/sso/oidc", "/test/jwt/result").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/sso/providers/**").permitAll()
                        .antMatchers("/api/**", "/admin/**").hasRole("ADMIN")
                        .antMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )
                // existing local form login
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/user/dashboard", true)
                        .permitAll()
                )
                // OIDC login remains
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/user/dashboard", true)
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
                )
                // SAML login remains
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .defaultSuccessUrl("/user/dashboard", true)
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .headers(headers -> headers.cacheControl(cache -> cache.disable()))
                .exceptionHandling().accessDeniedPage("/access-denied");

        return http.build();
    }



    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return userRequest -> {
            OidcUser oidcUser = delegate.loadUser((OidcUserRequest) userRequest);
            // you can map OIDC claims here if needed (e.g., save to DB)
            System.out.println("Logged in OIDC user: " + oidcUser.getEmail());
            return oidcUser;
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
