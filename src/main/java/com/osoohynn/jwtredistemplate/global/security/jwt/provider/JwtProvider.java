package com.osoohynn.jwtredistemplate.global.security.jwt.provider;


import com.osoohynn.jwtredistemplate.domain.auth.repository.RefreshTokenRepository;
import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import com.osoohynn.jwtredistemplate.domain.user.error.UserError;
import com.osoohynn.jwtredistemplate.domain.user.repository.UserRepository;
import com.osoohynn.jwtredistemplate.global.exception.CustomException;
import com.osoohynn.jwtredistemplate.global.security.CustomUserDetails;
import com.osoohynn.jwtredistemplate.global.security.jwt.config.JwtProperties;
import com.osoohynn.jwtredistemplate.global.security.jwt.enums.JwtType;
import com.osoohynn.jwtredistemplate.global.security.jwt.error.JwtError;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;

@Component
@RequiredArgsConstructor
public class JwtProvider {
    private SecretKey key;
    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostConstruct
    protected void init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecretKey()));
    }

    public String extractToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");

        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        }

        return null;
    }

    public Authentication getAuthentication (String token) {
        Jws<Claims> claims = getClaims(token);

        if (getType(token) != JwtType.ACCESS) {
            throw new CustomException(JwtError.INVALID_JWT_TOKEN);
        }

        User user = userRepository.findByUsername(claims.getBody().getSubject())
                .orElseThrow(() -> new CustomException(UserError.USER_NOT_FOUND));

        UserDetails userDetails = new CustomUserDetails(user);

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    public Jws<Claims> getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            throw new CustomException(JwtError.EXPIRED_JWT_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new CustomException(JwtError.UNSUPPORTED_JWT_TOKEN);
        } catch (MalformedJwtException e) {
            throw new CustomException(JwtError.MALFORMED_JWT_TOKEN);
        } catch (IllegalArgumentException e) {
            throw new CustomException(JwtError.INVALID_JWT_TOKEN);
        }
    }

    public JwtType getType(String token) {
        return JwtType.valueOf(Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getHeader()
                .get(Header.JWT_TYPE).toString()
        );
    }
}
