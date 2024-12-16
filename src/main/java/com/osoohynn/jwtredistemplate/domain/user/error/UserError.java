package com.osoohynn.jwtredistemplate.domain.user.error;

import com.osoohynn.jwtredistemplate.global.exception.CustomError;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserError implements CustomError {
    USER_NOT_FOUND(401, "user not fount"),
    WRONG_PASSWORD(401, "wrong password"),
    USERNAME_DUPLICATION(401, "user duplicate"),
    ;

    private final int status;
    private final String message;
}
