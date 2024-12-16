package com.osoohynn.jwtredistemplate.domain.auth.dto.request;

public record LoginRequest(
        String username,
        String password
) {
}
