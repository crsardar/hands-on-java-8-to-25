package com.crsardar.java.api;

import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Protected APIs", description = "Require Authorization: Bearer <JWT>")
@ApiResponse(responseCode = "401", description = "Missing, malformed, expired or forged token")
public class GreetingController {

    /** Any valid token. Shows how to read claims from the verified JWT. */
    @GetMapping("/hello")
    @Operation(summary = "Greets the caller and echoes claims from the JWT")
    @ApiResponse(responseCode = "200", description = "OK")
    public Map<String, Object> hello(@Parameter(hidden = true) @AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "message", "Hello, " + jwt.getSubject(),
                "issuer", jwt.getClaimAsString("iss"), // getIssuer() needs a URL; ours is a plain string
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt());
    }
}
