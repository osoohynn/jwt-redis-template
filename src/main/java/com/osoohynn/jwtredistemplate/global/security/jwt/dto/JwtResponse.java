package com.osoohynn.jwtredistemplate.global.security.jwt.dto;

public record JwtResponse(
        String accessToken,
        String refreshToken
) {
}
