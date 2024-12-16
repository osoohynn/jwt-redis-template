package com.osoohynn.jwtredistemplate.domain.user.service;


import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import com.osoohynn.jwtredistemplate.domain.user.dto.UserResponse;
import com.osoohynn.jwtredistemplate.global.security.UserAuthHolder;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserAuthHolder userAuthHolder;

    public UserResponse getMe() {
        User user = userAuthHolder.getUser();
        return UserResponse.of(user);
    }

}
