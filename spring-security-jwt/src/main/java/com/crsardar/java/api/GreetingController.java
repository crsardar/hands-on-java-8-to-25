package com.crsardar.java.api;

import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Protected APIs", description = "Require Authorization: Bearer <JWT>")
@ApiResponse(responseCode = "401", description = "Missing, malformed, expired or forged token")
public class GreetingController {

    /** Any valid token. Shows how to read claims from the verified JWT. */
    @GetMapping("/hello")
    @Operation(summary = "Greets the caller and echoes claims from the JWT (any role)")
    @ApiResponse(responseCode = "200", description = "OK")
    public Map<String, Object> hello(@Parameter(hidden = true) @AuthenticationPrincipal Jwt jwt,
                                     @Parameter(hidden = true) JwtAuthenticationToken authentication) {
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return Map.of(
                "message", "Hello, " + jwt.getSubject(),
                "authorities", authorities,
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt());
    }

    /** Protected by the URL rule /api/admin/** -> hasRole('ADMIN') in SecurityConfig. */
    @GetMapping("/admin/stats")
    @Operation(summary = "Admin statistics (ROLE_ADMIN, enforced by URL rule)")
    @ApiResponse(responseCode = "200", description = "OK")
    @ApiResponse(responseCode = "403", description = "Valid token but not ROLE_ADMIN")
    public Map<String, Object> adminStats() {
        return Map.of("activeInterviews", 42, "status", "ok");
    }

    /** Protected by method security instead of a URL rule. */
    @DeleteMapping("/reports/{id}")
    @Operation(summary = "Delete a report")
    @ApiResponse(responseCode = "200", description = "Deleted")
    @ApiResponse(responseCode = "403", description = "Valid token but not ROLE_ADMIN")
    public Map<String, Object> deleteReport(@PathVariable long id) {
        return Map.of("deleted", id);
    }
}
