package com.osoohynn.jwtredistemplate.domain.auth.controller;


import com.osoohynn.jwtredistemplate.domain.auth.dto.request.LoginRequest;
import com.osoohynn.jwtredistemplate.domain.auth.dto.request.RefreshRequest;
import com.osoohynn.jwtredistemplate.domain.auth.dto.request.SignUpRequest;
import com.osoohynn.jwtredistemplate.domain.auth.service.AuthService;
import com.osoohynn.jwtredistemplate.global.security.jwt.dto.JwtResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-up")
    public void signUp(@RequestBody SignUpRequest request) {
        authService.signUp(request);
    }

    @PostMapping("/sign-in")
    public JwtResponse login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public JwtResponse refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request);
    }

}
