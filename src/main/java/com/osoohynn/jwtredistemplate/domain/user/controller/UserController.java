package com.osoohynn.jwtredistemplate.domain.user.controller;


import com.osoohynn.jwtredistemplate.domain.user.dto.UserResponse;
import com.osoohynn.jwtredistemplate.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public UserResponse getMe() {
        return userService.getMe();
    }
}
