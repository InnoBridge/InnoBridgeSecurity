package io.github.innobridge.security.config;

import io.github.innobridge.security.model.ExpirationTime;
import io.github.innobridge.security.security.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import io.github.innobridge.security.service.MongoUserService;
import io.github.innobridge.security.service.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import static io.github.innobridge.security.constants.HTTPConstants.*;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

@Configuration
public class InnoBridgeSecurityConfig {

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new UsernameEmailPasswordAuthenticationProvider();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserService userService() {
        return new MongoUserService();
    }

    @Bean
    @Qualifier("defaultAccessExpirationTime")
    public ExpirationTime defaultAccessExpirationTime() {
        return new ExpirationTime(0, 1, 0, 0); // Default access token expiration time: 1 hour
    }

    @Bean
    @Qualifier("defaultRefreshExpirationTime")
    public ExpirationTime defaultRefreshExpirationTime() {
        return new ExpirationTime(10, 10, 0, 0); // Default refresh token expiration time: 10 hours
    }

    @Lazy
    @Bean
    public JwtUtils jwtUtils(@Value("${JWT_ACCESS_SIGNING_KEY}") String accessSigningKey,
                             @Value("${JWT_REFRESH_SIGNING_KEY}") String refreshSigningKey,
                             UserService userService,
                             @Qualifier("defaultAccessExpirationTime") ExpirationTime accessExpirationTime,
                             @Qualifier("defaultRefreshExpirationTime") ExpirationTime refreshExpirationTime) {
        return new JwtUtils(accessSigningKey,
                refreshSigningKey,
                userService,
                accessExpirationTime,
                refreshExpirationTime);
    }

    @Bean
    public UsernameEmailPasswordAuthenticationFilter usernameEmailPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new UsernameEmailPasswordAuthenticationFilter(authenticationManager);
    }

    @Bean
    public UsernameEmailPasswordRegistrationFilter usernameEmailPasswordRegistrationFilter() {
        return new UsernameEmailPasswordRegistrationFilter();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtils jwtUtils) {
        return new JwtAuthenticationFilter(jwtUtils, SIGNOUT_URL, REFRESH_TOKEN_URL);
    }

    @Bean
    public RefreshTokenFilter refreshTokenFilter(JwtUtils jwtUtils) {
        return new RefreshTokenFilter();
    }

    @Bean
    public LogoutFilter logoutFilter() {
        return new LogoutFilter();
    }

    @Lazy
    @Bean
    public CustomOAuth2SuccessHandler customOAuth2SuccessHandler() {
        return new CustomOAuth2SuccessHandler();
    }

    @Lazy
    @Bean
    public ClientRegistration googleClientRegistration(
            @Value("${GOOGLE_CLIENT_ID}") String googleClientId,
            @Value("${GOOGLE_CLIENT_SECRET}") String googleClientSecret,
            @Value("${OAUTH2_REDIRECT_BASE_URI}") String baseRedirectUri) {
        System.out.println("hi googleClientRegistration" + Thread.currentThread().getStackTrace());
        return ClientRegistration.withRegistrationId(GOOGLE_ID)
                .clientId(googleClientId)
                .clientSecret(googleClientSecret)
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .redirectUri(baseRedirectUri + GOOGLE_REDIRECT_URI_TEMPLATE)
                .scope(GOOGLE_SCOPES)
                .authorizationUri(GOOGLE_AUTHORIZATION_URI)
                .tokenUri(GOOGLE_TOKEN_URI)
                .userInfoUri(GOOGLE_USER_INFO_URI)
                .jwkSetUri(GOOGLE_JWK_SET_URI)
                .userNameAttributeName(OAUTH2_USER_NAME_ATTRIBUTE)
                .clientName(GOOGLE_CLIENT_NAME)
                .build();
    }

}
