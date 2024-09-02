package io.github.innobridge.security.model;

import lombok.Data;

@Data
public class AccessTokenResponse {
    private String accessToken;
    private long expiresIn;

    public AccessTokenResponse(String accessToken, long expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
    }
}
