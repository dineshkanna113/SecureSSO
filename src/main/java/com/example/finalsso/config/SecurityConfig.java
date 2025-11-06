package com.example.finalsso.config;

import com.example.finalsso.config.CustomAuthenticationSuccessHandler;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.service.UserCompanyMapper;
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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final UserCompanyMapper userCompanyMapper;

    public SecurityConfig(UserCompanyMapper userCompanyMapper) {
        this.userCompanyMapper = userCompanyMapper;
    }

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
                .addFilterBefore(new CompanyContextFilter(userCompanyMapper), 
                                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // Public routes
                        .antMatchers("/register", "/css/**", "/js/**", "/images/**", "/login", "/login/username", 
                                     "/login/sso", "/sso/oauth2/authorize", "/sso/oauth2/callback", 
                                     "/sso/saml2/authenticate", "/sso/saml2/acs", "/sso/jwt/authenticate", 
                                     "/sso/jwt/callback", "/sso/jwt/login", "/sso/jwt/verify", 
                                     "/test/sso/jwt", "/test/sso/jwt/**", "/test/sso/oidc", "/test/jwt/result",
                                     "/error", "/access-denied").permitAll()
                        // Password pages (permit all - will be validated in controller)
                        .antMatchers("/super-admin/password", "/*/password").permitAll()
                        .antMatchers(HttpMethod.POST, "/super-admin/password", "/*/password").permitAll()
                        // Super admin test route (for debugging)
                        .antMatchers("/super-admin/test").hasAnyRole("SUPER_ADMIN", "CUSTOMER_ADMIN", "END_USER")
                        // Super admin routes
                        .antMatchers("/super-admin/**").hasRole("SUPER_ADMIN")
                        // Company-based customer admin routes
                        .antMatchers("/*/customer-admin/**").hasRole("CUSTOMER_ADMIN")
                        // Company-based end user routes
                        .antMatchers("/*/enduser/**").hasAnyRole("CUSTOMER_ADMIN", "END_USER")
                        // Legacy API routes (for backward compatibility)
                        .antMatchers(HttpMethod.GET, "/api/sso/providers/**").permitAll()
                        .antMatchers("/api/**").hasAnyRole("SUPER_ADMIN", "CUSTOMER_ADMIN")
                        // Legacy admin routes (for backward compatibility)
                        .antMatchers("/admin/**").hasAnyRole("SUPER_ADMIN", "CUSTOMER_ADMIN")
                        // Legacy user routes (for backward compatibility)
                        .antMatchers("/user/**").hasAnyRole("SUPER_ADMIN", "CUSTOMER_ADMIN", "END_USER")
                        .anyRequest().authenticated()
                )
                // Form login - will redirect based on username lookup
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(authenticationSuccessHandler())
                        .permitAll()
                )
                // OIDC login
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/login", true)
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
                )
                // SAML login
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .defaultSuccessUrl("/login", true)
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
                .exceptionHandling(exception -> exception
                    .accessDeniedPage("/access-denied")
                    .authenticationEntryPoint((request, response, authException) -> {
                        response.sendRedirect("/login?error=access_denied");
                    })
                );

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
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(userCompanyMapper);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
