package com.crsardar.java.config;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.crsardar.java.user.ActiveAccountJwtValidator;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Stateless JWT security.
 *
 * <p>Request flow for a protected endpoint:
 * <pre>
 *   Authorization: Bearer &lt;jwt&gt;
 *     -> BearerTokenAuthenticationFilter   (extracts the token from the header)
 *     -> JwtAuthenticationProvider          (JwtDecoder: verify signature, exp/nbf, iss,
 *                                            then subject exists in user table and is ACTIVE)
 *     -> JwtAuthenticationConverter         ("roles" claim -> ROLE_* authorities)
 *     -> SecurityContextHolder              (JwtAuthenticationToken for this request only)
 *     -> AuthorizationFilter                (URL rules), then @PreAuthorize (method rules)
 * </pre>
 * Missing/invalid token -> 401 + {@code WWW-Authenticate: Bearer ...};
 * valid token without the required role -> 403.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    static final String ROLES_CLAIM = "roles";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // No cookies/sessions -> browsers can't send credentials automatically -> CSRF not applicable
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(HttpMethod.POST, "/api/auth/token").permitAll()
                        .requestMatchers("/error").permitAll()
                        // Swagger UI and the OpenAPI JSON it renders; the APIs themselves stay protected
                        .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                ); // picks up the JwtDecoder + converter beans below
        return http.build();
    }

    // ---------- Token verification (every incoming request) ----------

    @Bean
    SecretKey jwtSigningKey(JwtProperties props) {
        byte[] keyBytes = Base64.getDecoder().decode(props.secret());
        if (keyBytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be at least 256 bits for HS256");
        }
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKey jwtSigningKey, JwtProperties props,
                          ActiveAccountJwtValidator activeAccountValidator) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSigningKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        // Validators run only after the signature is verified, in this order:
        //   1. exp/nbf (60s clock skew) + iss       - cheap, no I/O
        //   2. subject exists in user table + ACTIVE - one lookup per request
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.issuer()),
                activeAccountValidator));
        return decoder;
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        // By default Spring reads "scope"/"scp" and prefixes SCOPE_; we use a "roles" claim instead
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(ROLES_CLAIM);
        authorities.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    // ---------- Token issuing (login endpoint only) ----------

    @Bean
    JwtEncoder jwtEncoder(SecretKey jwtSigningKey) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtSigningKey));
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // bcrypt by default
    }

    /**
     * Used only by the login endpoint to check username/password.
     * Users come from {@code UserAccountDetailsService}, which reads the user table.
     */
    @Bean
    AuthenticationManager authenticationManager(UserDetailsService uds, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(uds);
        provider.setPasswordEncoder(encoder);
        return new ProviderManager(provider);
    }
}
