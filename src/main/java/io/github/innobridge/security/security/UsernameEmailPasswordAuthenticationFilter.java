package io.github.innobridge.security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

import io.github.innobridge.security.model.AccessTokenResponse;
import io.github.innobridge.security.model.SigninRequest;
import io.github.innobridge.security.model.UsernameEmailPasswordAuthenticationToken;
import io.github.innobridge.security.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static io.github.innobridge.security.constants.HTTPConstants.*;
import static io.github.innobridge.security.model.TokenType.ACCESS_TOKEN;
import static io.github.innobridge.security.model.TokenType.REFRESH_TOKEN;

@Component
public class UsernameEmailPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // @Autowired
    // private AuthenticationController authenticationController;
    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtils jwtUtils;
    
    public UsernameEmailPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        setFilterProcessesUrl(SIGNIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        SigninRequest signinRequest = extractSigninRequest(request);

        String username = signinRequest.getUsername();
        String email = signinRequest.getEmail();
        String password = signinRequest.getPassword();

        if ((username == null || username.isEmpty()) && (email == null || email.isEmpty())) {
            throw new AuthenticationServiceException("Authentication failed: need both username or email.");
        }

        if (password == null || password.isEmpty()) {
            throw new AuthenticationServiceException("Authentication failed: need password.");
        }

        boolean withUsername = (username != null && !username.isEmpty());
        String principal = withUsername ? username : email;

        UsernameEmailPasswordAuthenticationToken authRequest = new UsernameEmailPasswordAuthenticationToken(principal, password, withUsername);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        SecurityContextHolder.getContext().setAuthentication(authResult);

        // ResponseEntity<?> responseEntity = authenticationController.authenticateUser(null, response);

        UsernameEmailPasswordAuthenticationToken authentication = (UsernameEmailPasswordAuthenticationToken) authResult;
        String accessToken = jwtUtils.generateToken(authentication, ACCESS_TOKEN);
        String refreshToken = jwtUtils.generateToken(authentication, REFRESH_TOKEN);

        userService.updateTokens(authentication.getId(), accessToken, refreshToken);

        // Set refresh token in HTTP-only cookie
        Cookie refreshTokenCookie = new Cookie(REFRESH_COOKIE, refreshToken);
        refreshTokenCookie.setHttpOnly(true); // prevents JavaScript from accessing the cookie
        refreshTokenCookie.setSecure(true); // should be set to true in production
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) jwtUtils.getRefreshTokenExpiration().toSeconds()); // Evicts the cookie from browser when the token expires
        response.addCookie(refreshTokenCookie);

        ResponseEntity<?> responseEntity = ResponseEntity.ok(
            new AccessTokenResponse(accessToken, jwtUtils.getAccessTokenExpiration().toSeconds())
        );

        response.setContentType(CONTENT_TYPE);
        response.setStatus(responseEntity.getStatusCode().value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseEntity.getBody()));
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        ResponseEntity<String> responseEntity = ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Error: " + failed.getMessage());

        response.setContentType(CONTENT_TYPE);
        response.setStatus(responseEntity.getStatusCode().value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseEntity.getBody()));
    }

    private SigninRequest extractSigninRequest(HttpServletRequest request) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(request.getInputStream(), SigninRequest.class);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Authentication failed: unable to read request body.", e);
        }
    }
}

