package io.github.innobridge.security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.innobridge.security.model.SignupRequest;
import io.github.innobridge.security.model.SignupResponse;
import io.github.innobridge.security.model.User;
import io.github.innobridge.security.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

import static io.github.innobridge.security.constants.HTTPConstants.CONTENT_TYPE;
import static io.github.innobridge.security.constants.HTTPConstants.SIGNUP_URL;

@Component
public class UsernameEmailPasswordRegistrationFilter extends OncePerRequestFilter {

    private String url = SIGNUP_URL;

    @Autowired
    private UserService userService;

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (url.equals(request.getRequestURI()) && "post".equalsIgnoreCase(request.getMethod())) {
            ObjectMapper objectMapper = new ObjectMapper();
            SignupRequest signupRequest = objectMapper.readValue(request.getInputStream(), SignupRequest.class);

            // Check if username or email is already taken
            if (userService.existsByUsername(signupRequest.getUsername())) {
                sendErrorResponse(response, "Error: Username is already taken!");
                return;
            }

            if (userService.existsByEmail(signupRequest.getEmail())) {
                sendErrorResponse(response, "Error: Email is already in use!");
                return;
            }

            // Create new user
            User user = new User();
            user.setUsername(signupRequest.getUsername());
            user.setEmail(signupRequest.getEmail());
            user.setPassword(signupRequest.getPassword());
            user.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
            user.setAccountNonExpired(true);
            user.setAccountNonLocked(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);

            User savedUser = userService.saveUser(user);

            // Send success response
            sendSuccessResponse(response, new SignupResponse(savedUser.getId(), savedUser.getUsername(), savedUser.getEmail()));
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(CONTENT_TYPE);
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }

    private void sendSuccessResponse(HttpServletResponse response, SignupResponse signupResponse) throws IOException {
        // Create an Authentication object
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                signupResponse.getUsername(), null, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

        // Set the Authentication object in the SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        response.setStatus(HttpStatus.CREATED.value());
        response.setContentType(CONTENT_TYPE);
        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(signupResponse));
    }
}
