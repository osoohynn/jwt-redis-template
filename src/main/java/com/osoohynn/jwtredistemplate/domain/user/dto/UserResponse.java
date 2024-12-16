package com.osoohynn.jwtredistemplate.domain.user.dto;

import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import com.osoohynn.jwtredistemplate.domain.user.domain.enums.UserRole;

public record UserResponse(
        Long id,
        String username,
        UserRole role
) {
    public static UserResponse of(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getRole()
        );
    }
}
