package com.crsardar.java;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.crsardar.java.user.AccountStatus;
import com.crsardar.java.user.UserAccountRepository;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
class JwtSecurityIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    SecretKey jwtSigningKey;

    @Autowired
    UserAccountRepository userAccounts;

    // ---------- login ----------

    @Test
    void loginWithValidCredentialsReturnsBearerToken() throws Exception {
        mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"crsardar","password":"Chitta@123"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void loginWithWrongPasswordIs401() throws Exception {
        mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"crsardar","password":"nope"}"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid username or password"));
    }

    // ---------- Authorization header on protected endpoints ----------

    @Test
    void missingAuthorizationHeaderIs401WithBearerChallenge() throws Exception {
        mvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
    }

    @Test
    void validTokenReachesEndpointAndExposesClaims() throws Exception {
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(login("crsardar", "Chitta@123"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, crsardar"))
                .andExpect(jsonPath("$.issuer").value("com.crsardar.java"));
    }

    // ---------- tokens that must be rejected ----------

    @Test
    void malformedTokenIs401() throws Exception {
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    @Test
    void expiredTokenIs401() throws Exception {
        Instant past = Instant.now().minus(1, ChronoUnit.HOURS);
        String token = sign(jwtSigningKey, "com.crsardar.java", past, past.plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("expired")));
    }

    @Test
    void tokenSignedWithAnotherKeyIs401() throws Exception {
        SecretKey attackerKey = new SecretKeySpec("an-attacker-key-that-is-32-bytes!!".getBytes(), "HmacSHA256");
        Instant now = Instant.now();
        String forged = sign(attackerKey, "com.crsardar.java", now, now.plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenFromUntrustedIssuerIs401() throws Exception {
        Instant now = Instant.now();
        String token = sign(jwtSigningKey, "https://evil.example", now, now.plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isUnauthorized());
    }

    // ---------- subject must exist in the user table and be ACTIVE ----------

    @Test
    void validlySignedTokenForUnknownUserIs401() throws Exception {
        Instant now = Instant.now();
        String token = sign(jwtSigningKey, "com.crsardar.java", "ghost", now, now.plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("not active")));
    }

    @Test
    void validlySignedTokenForDisabledUserIs401() throws Exception {
        Instant now = Instant.now();
        String token = sign(jwtSigningKey, "com.crsardar.java", "bob", now, now.plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disabledUserCannotLogIn() throws Exception {
        mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"bob","password":"bob123"}"""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void existingTokenStopsWorkingOnceAccountIsDisabledAndWorksAgainWhenReactivated() throws Exception {
        String userToken = login("crsardar", "Chitta@123");
        String otherToken = login("alice", "alice123");
        try {
            mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                    .andExpect(status().isOk());

            changeStatus(otherToken, "crsardar", "LOCKED")
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("LOCKED"));

            // Same token, still signed and unexpired - now rejected
            mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                    .andExpect(status().isUnauthorized());

            changeStatus(otherToken, "crsardar", "ACTIVE").andExpect(status().isOk());

            mvc.perform(get("/api/hello").header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                    .andExpect(status().isOk());
        } finally {
            userAccounts.updateStatus("crsardar", AccountStatus.ACTIVE); // never leak state into other tests
        }
    }

    @Test
    void changingStatusOfUnknownUserIs404() throws Exception {
        changeStatus(login("alice", "alice123"), "ghost", "DISABLED")
                .andExpect(status().isNotFound());
    }

    // ---------- Swagger / OpenAPI ----------

    @Test
    void swaggerUiIsPublic() throws Exception {
        mvc.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isOk());
    }

    @Test
    void openApiDocsArePublicAndListAllApisWithBearerScheme() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/auth/token'].post").exists())
                .andExpect(jsonPath("$.paths['/api/auth/token'].post.security").isEmpty())
                .andExpect(jsonPath("$.paths['/api/hello'].get").exists())
                .andExpect(jsonPath("$.paths['/api/hello'].get.parameters").doesNotExist())
                .andExpect(jsonPath("$.paths['/api/users/{username}/status'].patch").exists())
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                .andExpect(jsonPath("$.security[0].bearerAuth").exists());
    }

    // ---------- helpers ----------

    private String login(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.access_token");
    }

    private ResultActions changeStatus(String token, String username, String status) throws Exception {
        return mvc.perform(patch("/api/users/{username}/status", username)
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"%s\"}".formatted(status)));
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String sign(SecretKey key, String issuer, Instant issuedAt, Instant expiresAt) {
        return sign(key, issuer, "crsardar", issuedAt, expiresAt);
    }

    private static String sign(SecretKey key, String issuer, String subject, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();
        return new NimbusJwtEncoder(new ImmutableSecret<>(key))
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }
}
