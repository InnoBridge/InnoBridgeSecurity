package io.github.innobridge.security.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SigninRequest {

    private String username;

    @Email
    private String email;

    @NotBlank
    private String password;
}
