package com.osoohynn.jwtredistemplate.domain.user.repository;

import com.osoohynn.jwtredistemplate.domain.user.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);

}
