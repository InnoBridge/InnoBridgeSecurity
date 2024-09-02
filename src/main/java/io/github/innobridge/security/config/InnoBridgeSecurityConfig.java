package io.github.innobridge.security.config;

import io.github.innobridge.security.model.ExpirationTime;
import io.github.innobridge.security.security.JwtUtils;
import io.github.innobridge.security.security.UsernameEmailPasswordAuthenticationFilter;
import io.github.innobridge.security.security.UsernameEmailPasswordAuthenticationProvider;
import io.github.innobridge.security.security.UsernameEmailPasswordRegistrationFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import io.github.innobridge.security.service.ApplicationSpecificSpringComponentScanMarker;
import io.github.innobridge.security.service.MongoUserService;
import io.github.innobridge.security.service.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    @Bean
    public JwtUtils jwtUtils(@Value("${JWT_ACCESS_SIGNING_KEY}") String accessSigningKey,
                             @Value("${JWT_REFRESH_SIGNING_KEY}") String refreshSigningKey,
                             UserService userService,
                             @Qualifier("defaultAccessExpirationTime") ExpirationTime accessExpirationTime,
                             @Qualifier("defaultRefreshExpirationTime") ExpirationTime refreshExpirationTime) {
        System.out.println("accessExpirationTime: " + accessExpirationTime);
        System.out.println("refreshExpirationTime: " + refreshExpirationTime);
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

}
