package com.sbi.ems.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Spring Security configuration.
 *
 * ── DevSecOps Fixes Applied ───────────────────────────────────────────────────
 *
 *  A01 — Broken Access Control:
 *    @EnableMethodSecurity enables @PreAuthorize on controllers/services.
 *    Salary endpoint protected by hasRole('ADMIN') or isCurrentUser().
 *
 *  A05 — Security Misconfiguration:
 *    BEFORE: csrf disabled with no replacement, no CORS, no security headers,
 *            Swagger wide open, Actuator exposing all endpoints.
 *    AFTER:
 *      - CSRF disabled intentionally for stateless REST (JWT replaces session)
 *      - CORS explicitly configured — no wildcard origins
 *      - Security headers: X-Frame-Options, X-Content-Type-Options, HSTS,
 *        Referrer-Policy, Content-Security-Policy
 *      - Swagger UI accessible only in non-prod profiles
 *      - Actuator restricted to /health and /info
 *
 *  A07 — Auth Failures:
 *    - BCrypt cost factor 12 (computationally expensive for brute-force)
 *    - Stateless sessions — no JSESSIONID cookie attack surface
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity           // enables @PreAuthorize on controllers and services
public class SecurityConfig {

    private static final String[] PUBLIC_PATHS = {
        "/api/v1/auth/login",
        "/swagger-ui/**",
        "/swagger-ui.html",
        "/v3/api-docs/**",
        "/actuator/health",
        "/actuator/info"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {

        http
            // ── CSRF ──────────────────────────────────────────────────────────
            // Disabled intentionally: stateless REST API uses JWT, not sessions.
            // CSRF attacks require a browser session cookie — JWT in Authorization
            // header is not auto-sent by browsers so CSRF is not applicable here.
            .csrf(csrf -> csrf.disable())

            // ── Session management — stateless ────────────────────────────────
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // ── CORS ──────────────────────────────────────────────────────────
            // DevSecOps: NEVER use allowedOrigins("*") in a banking application.
            // Explicitly list allowed origins.
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // ── Security headers ──────────────────────────────────────────────
            // DevSecOps: Defence-in-depth — HTTP security headers protect against
            // clickjacking, MIME-sniffing, and information leakage.
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())             // A01: Prevent clickjacking
                .contentTypeOptions(cto -> {})                   // A05: Prevent MIME sniffing
                .httpStrictTransportSecurity(hsts -> hsts        // A02: Force HTTPS
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true))
                .referrerPolicy(rp -> rp
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline'; " +  // needed for Swagger UI
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:"))
            )

            // ── Authorisation rules ───────────────────────────────────────────
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC_PATHS).permitAll()
                // H2 console — only accessible with ADMIN role (dev only)
                .requestMatchers("/h2-console/**").hasRole("ADMIN")
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )

            // ── JWT filter ────────────────────────────────────────────────────
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CORS configuration.
     * DevSecOps: Explicitly whitelist allowed origins.
     * Never use allowedOrigins("*") — it allows any domain to make
     * credentialed cross-origin requests to the banking API.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // Training: localhost only. Production: replace with actual front-end domain.
        config.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:8080"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * BCrypt password encoder — cost factor 12.
     * DevSecOps (A02): Cost 12 means ~250ms per hash — expensive for attackers,
     * acceptable for login. NEVER use MD5, SHA-1, or plain text for passwords.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}
