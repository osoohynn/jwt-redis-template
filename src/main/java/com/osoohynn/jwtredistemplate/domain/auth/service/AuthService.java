package com.osoohynn.jwtredistemplate.domain.auth.service;


import com.osoohynn.jwtredistemplate.domain.auth.dto.request.LoginRequest;
import com.osoohynn.jwtredistemplate.domain.auth.dto.request.SignUpRequest;
import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import com.osoohynn.jwtredistemplate.domain.user.error.UserError;
import com.osoohynn.jwtredistemplate.domain.user.repository.UserRepository;
import com.osoohynn.jwtredistemplate.global.exception.CustomException;
import com.osoohynn.jwtredistemplate.global.security.jwt.dto.JwtResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(SignUpRequest request) {
        String username = request.Username();
        String password = passwordEncoder.encode(request.Password());

        if (userRepository.existsByUsername(username)) {
            throw new CustomException(UserError.USERNAME_DUPLICATION);
        }

        User user = User.builder()
                .username(username)
                .password(password)
                .build();

        userRepository.save(user);
    }

    public JwtResponse login(LoginRequest request) {
        String username = request.username();
        String password = request.password();

        if (!userRepository.existsByUsername(username)) {
            throw new CustomException(UserError.USER_NOT_FOUND);
        }

        if (!passwordEncoder.matches(password, request.password())) {
            throw new CustomException(UserError.WRONG_PASSWORD);
        }
    }
}
