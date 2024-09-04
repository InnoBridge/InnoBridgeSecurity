package io.github.innobridge.security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.innobridge.security.model.AccessTokenResponse;
import io.github.innobridge.security.model.User;
import io.github.innobridge.security.model.UsernameEmailPasswordAuthenticationToken;
import io.github.innobridge.security.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Optional;
import java.util.Map;

import static io.github.innobridge.security.constants.HTTPConstants.CONTENT_TYPE;
import static io.github.innobridge.security.constants.HTTPConstants.REFRESH_COOKIE;
import static io.github.innobridge.security.model.TokenType.ACCESS_TOKEN;
import static io.github.innobridge.security.model.TokenType.REFRESH_TOKEN;

public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    UserService userService;
    @Autowired
    JwtUtils jwtUtils;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        handle(request, response, authentication);
        clearAuthenticationAttributes(request);
    }

    /**
     * We are close to end of the OAuth2 flow, after the Client redirected the user to the OAuth2 provider,
     * after the user sends its credential/consent to the OAuth2 provider, the OAuth2 provider redirects the user back to the Client.
     * providing the authorization code/token to the Client to retrieve the users' information.
     * This method handles the successfull retrieval of the user's information from the OAuth2 provider.
     * Where we validate that the user's email matches the email in the database, and using the user's information
     * we generate the JWT access/refresh token, in which we redirect to the /oauth2/success endpoint otherwise
     * we redirect to the /oauth2/failure endpoint.
     */
    @Override
    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication oauthAuthentication) throws IOException {
        OAuth2AuthenticationToken oauth2Authentication = (OAuth2AuthenticationToken) oauthAuthentication;
        
        // Remove JSESSIONID cookie
        Cookie jSessionIdCookie = new Cookie("JSESSIONID", null);
        jSessionIdCookie.setPath("/");
        jSessionIdCookie.setHttpOnly(true);
        jSessionIdCookie.setMaxAge(0);
        response.addCookie(jSessionIdCookie);

        try {
            if (!Boolean.TRUE.equals(oauth2Authentication.getPrincipal().getAttribute("email_verified"))) {
                sendErrorResponse(response, "Email not verified");
                return;
            }

            String email = oauth2Authentication.getPrincipal().getAttribute("email");
            Optional<User> optionalUser = userService.getByEmail(email);
            
            if(optionalUser.isEmpty()) {
                sendErrorResponse(response, "User not found with email: " + email);
                return;
            }

            User user = optionalUser.get();
            UsernameEmailPasswordAuthenticationToken authentication = new UsernameEmailPasswordAuthenticationToken(user.getId(), user.getUsername(), user.getAuthorities());

            String accessToken = jwtUtils.generateToken(authentication, ACCESS_TOKEN);
            String refreshToken = jwtUtils.generateToken(authentication, REFRESH_TOKEN);

            userService.updateTokens(authentication.getId(), accessToken, refreshToken);

            // Set refresh token in HTTP-only cookie
            Cookie refreshTokenCookie = getRefreshTokenCookie(refreshToken);
            response.addCookie(refreshTokenCookie);

            // Create and send AccessTokenResponse
            AccessTokenResponse tokenResponse = new AccessTokenResponse(accessToken, jwtUtils.getAccessTokenExpiration().toSeconds());
            sendJsonResponse(response, tokenResponse);

        } catch (AuthenticationException e) {
            sendErrorResponse(response, e.getMessage());
        }
    }

    private Cookie getRefreshTokenCookie(String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(REFRESH_COOKIE, refreshToken);
        refreshTokenCookie.setHttpOnly(true); // prevents JavaScript from accessing the cookie
        refreshTokenCookie.setSecure(true); // should be set to true in production
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) jwtUtils.getRefreshTokenExpiration().toSeconds()); // Evicts the cookie from browser when the token expires
        return refreshTokenCookie;
    }

    private void sendErrorResponse(HttpServletResponse response, String errorMessage) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(CONTENT_TYPE);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getWriter(), Map.of("error", errorMessage));
    }

    private void sendJsonResponse(HttpServletResponse response, Object data) throws IOException {
        response.setContentType(CONTENT_TYPE);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getWriter(), data);
    }
}

