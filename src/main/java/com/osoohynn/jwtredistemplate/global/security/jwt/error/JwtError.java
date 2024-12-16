package com.osoohynn.jwtredistemplate.global.security.jwt.error;

import com.osoohynn.jwtredistemplate.global.exception.CustomError;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum JwtError implements CustomError {
    EXPIRED_JWT_TOKEN(401, "Expired JWT token"),
    INVALID_JWT_TOKEN(401, "Invalid JWT token"),
    UNSUPPORTED_JWT_TOKEN(401, "Unsupported JWT token"),
    MALFORMED_JWT_TOKEN(401, "Malformed JWT token"),
    INVALID_TOKEN_TYPE(401, "Invalid token type"),
    INVALID_REFRESH_TOKEN(401, "Invalid refresh token")
    ;

    private final int status;
    private final String message;
}
