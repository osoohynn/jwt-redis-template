package com.osoohynn.jwtredistemplate.domain.auth.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {
    private final RedisTemplate<String, String> redisTemplate;

    public void save(String username, String refreshToken) {
        redisTemplate.opsForValue().set("refreshToken:" + username, refreshToken);
    }

    public String findByUsername(String username) {
        return redisTemplate.opsForValue().get("refreshToken:" + username);
    }

    public Boolean existsByUserName(String username) {
        return redisTemplate.hasKey("refreshToken:" + username);
    }
}