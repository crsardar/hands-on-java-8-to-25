package com.crsardar.java.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

import org.springframework.context.annotation.Configuration;

/**
 * Swagger UI at /swagger-ui.html, OpenAPI JSON at /v3/api-docs.
 *
 * <p>Declares a global "bearerAuth" scheme so Swagger UI shows an <b>Authorize</b> button:
 * paste the access_token from POST /api/auth/token and every "Try it out" call sends
 * {@code Authorization: Bearer <token>}.
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Spring Security JWT demo",
                version = "0.0.1",
                description = "Every API except POST /api/auth/token requires `Authorization: Bearer <JWT>`. "
                        + "Get a token from /api/auth/token (crsardar/Chitta@123 or alice/alice123), "
                        + "then click **Authorize** and paste it."),
        security = @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH))
@SecurityScheme(
        name = OpenApiConfig.BEARER_AUTH,
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT")
public class OpenApiConfig {

    public static final String BEARER_AUTH = "bearerAuth";
}
