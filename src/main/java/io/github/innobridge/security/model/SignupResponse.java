package io.github.innobridge.security.model;

import lombok.Data;

@Data
public class SignupResponse {

    private String id;
    private String username;
    private String email;

    public SignupResponse(String id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
}
