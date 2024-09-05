package io.github.innobridge.security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import io.github.innobridge.security.model.User;
import io.github.innobridge.security.model.UsernameEmailPasswordAuthenticationToken;
import io.github.innobridge.security.service.UserService;

@Component
public class UsernameEmailPasswordAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * If username and password are provided will check if the user and password are valid
     * If email and password are provided will check if the email and password are valid
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernameEmailPasswordAuthenticationToken authRequest = (UsernameEmailPasswordAuthenticationToken) authentication;
        String principal = (String) authRequest.getPrincipal();
        String credentials = (String) authRequest.getCredentials();
        boolean withUsername = authRequest.isWithUsername();

        User user;

        if (withUsername) {
            user = userService.getByUsername(principal).orElseThrow(
                    () -> new AuthenticationServiceException("Invalid username/email or password"));
        } else {
            user = userService.getByEmail(principal).orElseThrow(
                    () -> new AuthenticationServiceException("Invalid username/email or password"));
        }

        if (!passwordEncoder.matches(credentials, user.getPassword())) {
            throw new AuthenticationServiceException("Invalid username/email or password");
        }
        return new UsernameEmailPasswordAuthenticationToken(user.getId(), user.getUsername(), user.getAuthorities());
    }

    /**
     * The AuthenticationManager will choose which AuthenticationProvider to use based if the provider supports the
     * implementation of the Authentication token.
     * In this case, the UsernameEmailPasswordAuthenticationToken is supported. And the AuthorizationManager will
     * use this provider to authenticate the user.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernameEmailPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
