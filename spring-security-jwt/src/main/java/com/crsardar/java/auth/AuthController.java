package com.crsardar.java.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The only public endpoint: exchanges username/password for a signed JWT. */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Obtain a JWT access token")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthController(AuthenticationManager authenticationManager, TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    @SecurityRequirements // empty = overrides the global bearerAuth requirement: no lock icon, no token sent
    @Operation(summary = "Exchange username/password for a JWT",
            description = "Demo users: crsardar/Chitta@123, alice/alice123 (bob/bob123 is DISABLED)")
    @ApiResponse(responseCode = "200", description = "Token issued")
    @ApiResponse(responseCode = "401", description = "Invalid username or password")
    public TokenResponse token(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password()));
        return tokenService.issue(authentication);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail onBadCredentials(AuthenticationException ex) {
        // Deliberately vague: don't reveal whether the username exists
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid username or password");
    }
}
