package io.github.innobridge.security.security;

import io.github.innobridge.security.model.UsernameEmailPasswordAuthenticationToken;
import io.github.innobridge.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static io.github.innobridge.security.constants.HTTPConstants.CONTENT_TYPE;
import static io.github.innobridge.security.constants.HTTPConstants.REFRESH_COOKIE;

public class LogoutFilter extends OncePerRequestFilter {

    @Autowired
    private UserService userService;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI().equals(jwtAuthenticationFilter.getSignoutUrl()) && request.getMethod().equals("POST")) {
            String userId = ((UsernameEmailPasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getId();
            userService.deleteTokens(userId);

            Cookie refreshTokenCookie = new Cookie(REFRESH_COOKIE, null);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(0); // Remove the refresh token from the user's browser by setting the cookie to expire immediately.
            response.addCookie(refreshTokenCookie);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(CONTENT_TYPE);
            response.getWriter().write("Signout successful");
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
