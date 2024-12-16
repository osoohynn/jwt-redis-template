package com.osoohynn.jwtredistemplate.global.security;

import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import com.osoohynn.jwtredistemplate.domain.user.error.UserError;
import com.osoohynn.jwtredistemplate.domain.user.repository.UserRepository;
import com.osoohynn.jwtredistemplate.global.exception.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException(UserError.USER_NOT_FOUND));
        return new CustomUserDetails(user);
    }
}
