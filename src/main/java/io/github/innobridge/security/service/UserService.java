package io.github.innobridge.security.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetailsService;
import io.github.innobridge.security.model.User;

public interface UserService extends UserDetailsService {

    Optional<User> getById(String id);

    Optional<User> getByUsername(String username);

    boolean existsByUsername(String username);

    Optional<User> getByEmail(String email);

    boolean existsByEmail(String email);

    User saveUser(User user);

    void updateTokens(String id, String accessToken, String refreshToken);

    void updateAccessToken(String id, String accessToken);

    void deleteTokens(String id);
    
}
