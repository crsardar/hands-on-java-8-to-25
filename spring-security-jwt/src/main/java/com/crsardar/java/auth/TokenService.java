package com.crsardar.java.auth;

import java.time.Instant;

import com.crsardar.java.config.MyProperties;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final JwtEncoder encoder;
    private final MyProperties props;

    public TokenService(JwtEncoder encoder, MyProperties props) {
        this.encoder = encoder;
        this.props = props;
    }

    public TokenResponse issue(Authentication authentication) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .subject(authentication.getName())
                .issuedAt(now)
                .expiresAt(now.plus(props.ttl()))
                .build();

        // Must state HS256 explicitly: NimbusJwtEncoder defaults to RS256
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(token, "Bearer", props.ttl().toSeconds());
    }
}
