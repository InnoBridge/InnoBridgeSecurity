package io.github.innobridge.security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.innobridge.security.constants.HTTPConstants;
import io.github.innobridge.security.model.AccessTokenResponse;
import io.github.innobridge.security.model.UsernameEmailPasswordAuthenticationToken;
import io.github.innobridge.security.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static io.github.innobridge.security.model.TokenType.ACCESS_TOKEN;

public class RefreshTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().equals(jwtAuthenticationFilter.getRefreshTokenUrl()) && request.getMethod().equals("POST")) {
            UsernameEmailPasswordAuthenticationToken authentication =
                (UsernameEmailPasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

            String accessToken = jwtUtils.generateToken(authentication, ACCESS_TOKEN);
            userService.updateAccessToken(authentication.getId(), accessToken);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(HTTPConstants.CONTENT_TYPE);
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.writeValue(response.getWriter(), new AccessTokenResponse(accessToken, jwtUtils.getAccessTokenExpiration().toSeconds()));
        } else {
            filterChain.doFilter(request, response);
        }
    }

}