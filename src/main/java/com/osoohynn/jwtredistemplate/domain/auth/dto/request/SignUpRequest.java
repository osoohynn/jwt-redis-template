package com.osoohynn.jwtredistemplate.domain.auth.dto.request;

public record SignUpRequest(
        String username,
        String password
) {
}
