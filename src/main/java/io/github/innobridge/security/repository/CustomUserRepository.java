package io.github.innobridge.security.repository;

import io.github.innobridge.security.model.User;

public interface CustomUserRepository {
    User updateUser(String id, User user);
    void updateTokens(String id, String accessToken, String refreshToken);
    void updateAccessToken(String id, String accessToken);
    void deleteTokens(String id);
}
