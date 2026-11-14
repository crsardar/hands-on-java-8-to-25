package com.crsardar.java.user;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Runs on every request inside {@code JwtDecoder.decode()}, after the signature has been verified:
 * the token's subject must exist in the user table and be ACTIVE.
 *
 * <p>This is what makes a disabled account lose access immediately, even though its JWT
 * is still correctly signed and not yet expired. Failure -> 401 {@code invalid_token}.
 */
@Component
public class MyJwtAccountValidator implements OAuth2TokenValidator<Jwt> {

    // Same message for "unknown" and "inactive": don't tell a token holder which one it is
    private static final OAuth2Error INACTIVE = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN, "The account for this token does not exist or is not active", null);

    private final UserAccountRepository repository;

    public MyJwtAccountValidator(UserAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        boolean active = repository.findByUsername(jwt.getSubject())
                .map(UserAccount::isActive)
                .orElse(false);
        return active ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(INACTIVE);
    }
}
