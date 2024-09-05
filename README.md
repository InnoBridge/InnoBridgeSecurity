# InnoBridge Security

## Motivation
The goal of this project is to simplify the process of bootstrapping authentication in your application with minimal coding. It provides authentication features such as username, email, password, JWT, and OAuth2 support, as described in [Securing Java Application with Spring Security, JWT and OpenID](https://www.linkedin.com/pulse/securing-java-application-spring-security-jwt-andopenid-yi-leng-yao-nn3pf/?trackingId=WlOlbqIcQdGhmU%2FXSC4jpA%3D%3D) by configuring a SecurityConfig file and setting a few environment variables.

## Features
- Username, email, and password authentication
- JWT authentication
- OpenID Connect Authentication

## Prerequisites

- Java Development Kit (JDK) 11 or later (exact version to be confirmed)
- Maven or Gradle
- MongoDB

## Installation

Add the InnoBridge Security dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.innobridge</groupId>
    <artifactId>security</artifactId>
    <version>{version}</version>
</dependency>
```

## Username, email, password and JWT authentication
Set the following environment variables:
```bash
export MONGO_DATABASE_URI=<your-mongo-database-uri>
export JWT_ACCESS_SIGNING_KEY=<your-jwt-access-signing-key>
export JWT_REFRESH_SIGNING_KEY=<your-jwt-refresh-signing-key>
```

Create the configuration file `SecurityConfig.java`

```java
@Configuration
@EnableWebSecurity
@Import(InnoBridgeSecurityConfig.class)
@EnableMongoRepositories(basePackages = {
        "io.github.innobridge.security.repository",
        <Location of your Mongo Repository>, // eg. "io.yilengyao.jwtauth.repository"
})
public class SecurityConfig implements WebMvcConfigurer {

 @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   UsernamePasswordAuthenticationFilter usernameEmailPasswordAuthenticationFilter,
                                                   UsernameEmailPasswordRegistrationFilter usernameEmailPasswordRegistrationFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   RefreshTokenFilter refreshTokenFilter,
                                                   LogoutFilter logoutFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers(WHITE_LIST_URL).permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)                )
                .oauth2Login(oauth2 ->
                        oauth2.clientRegistrationRepository(clientRegistrationRepository)// Ensure OAuth2 login is configured
                                .successHandler(customOAuth2SuccessHandler))
                .addFilterAt(usernameEmailPasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(usernameEmailPasswordRegistrationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(logoutFilter, RefreshTokenFilter.class);
        return http.build();
    }
```

The default Endpoints:
- POST /auth/signup: User signup with username, email and password.
- POST /auth/signin: When user is authenticated, an access token in response body and a refresh token in a cookie named `refresh-token` will be returned. The access and refresh token will be saved in database.
- POST /auth/refresh: Renew the access token using the refresh token. The new access token will be returned in response body and saved in database.
- POST /auth/signout: Clear the refresh token saved in database and clear the refresh token cookie.

To access protected endpoints the user needs to pass the access token in the Authorization header with the scheme `Bearer`.

### Override default configuration
You can override the default configuration by setting the following properties:
- Access token expiration time: `jwtUtils.setAccessTokenExpiration(new ExpirationTime(0, 2, 0, 0));`
- Refresh token expiration time: `jwtUtils.setRefreshTokenExpiration(new ExpirationTime(7, 0, 0, 0));`
- Signin url: `usernameEmailPasswordAuthenticationFilter.setFilterProcessesUrl("/auth/login");`
- Signup url: `usernameEmailPasswordRegistrationFilter.setUrl("/auth/register");`
- Signout url: `jwtAuthenticationFilter.setSignoutUrl("/auth/logout");`
- Renew access token url: `jwtAuthenticationFilter.setRefreshTokenUrl("/auth/tokenrefesh");`

eg.
```java
@Configuration
@EnableWebSecurity
@Import(InnoBridgeSecurityConfig.class)
@EnableMongoRepositories(basePackages = {
        "io.github.innobridge.security.repository",
        <Location of your Mongo Repository>, // eg. "io.yilengyao.jwtauth.repository"
})
public class SecurityConfig implements WebMvcConfigurer {

 @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   UsernamePasswordAuthenticationFilter usernameEmailPasswordAuthenticationFilter,
                                                   UsernameEmailPasswordRegistrationFilter usernameEmailPasswordRegistrationFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   RefreshTokenFilter refreshTokenFilter,
                                                   LogoutFilter logoutFilter) throws Exception {
        jwtUtils.setAccessTokenExpiration(new ExpirationTime(0, 2, 0, 0));
        jwtUtils.setRefreshTokenExpiration(new ExpirationTime(7, 0, 0, 0));
        usernameEmailPasswordAuthenticationFilter.setFilterProcessesUrl("/auth/login");
        usernameEmailPasswordRegistrationFilter.setUrl("/auth/register");
        jwtAuthenticationFilter.setSignoutUrl("/auth/logout");
        jwtAuthenticationFilter.setRefreshTokenUrl("/auth/tokenrefesh");
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers(WHITE_LIST_URL).permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)                )
                .oauth2Login(oauth2 ->
                        oauth2.clientRegistrationRepository(clientRegistrationRepository)// Ensure OAuth2 login is configured
                                .successHandler(customOAuth2SuccessHandler))
                .addFilterAt(usernameEmailPasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(usernameEmailPasswordRegistrationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(logoutFilter, RefreshTokenFilter.class);
        return http.build();
    }
}
```

### [Optional] Controller to scaffold OpenAPI
The following controller isn't required and does not provide any functionality, it provides scaffolding for the OpenAPI spec.
You can access the OpenAPI spec at `http://localhost:8080/swagger-ui/index.html` if you are running locally.
Or `https://<your-domain>/swagger-ui/index.html` if you are running in production.
```java
@Slf4j
@RestController
public class AuthenticationController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping(SIGNUP_URL)
    @ApiResponses(value = {
            @ApiResponse(responseCode = CREATED,
                    description = "Successful signup",
                    content = @Content(mediaType = CONTENT_TYPE,
                            schema = @Schema(implementation = SignupResponse.class)))
    })
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest, HttpServletResponse response) {
        return ResponseEntity.ok(response);
    }

    /**
     * When the username/email and password are validated during signin, an access token and refresh token are returned
     * to the user. The access token is used to authenticate the user for a short period of time, so it is passed back to
     * user in the response body along with the expiry time.
     * While the refresh token are longer lived and are stored in an HTTP-only cookie on the user's browser.
     */
    @PostMapping(SIGNIN_URL)
    @ApiResponses(value = {
            @ApiResponse(responseCode = CREATED, description = "Successful signin",
                    content = @Content(mediaType = CONTENT_TYPE,
                            schema = @Schema(implementation = AccessTokenResponse.class)))
    })
    public ResponseEntity<?> authenticateUser(@RequestBody SigninRequest signinRequest, HttpServletResponse response) {
        return ResponseEntity.ok(response);
    }

    @PostMapping(REFRESH_TOKEN_URL)
    @ApiResponses(value = {
            @ApiResponse(responseCode = CREATED, description = "Refresh token successful",
                    content = @Content(mediaType = CONTENT_TYPE,
                            schema = @Schema(implementation = AccessTokenResponse.class)))
    })
    public ResponseEntity<?> refreshToken(HttpServletResponse response) {
        return ResponseEntity.ok(response);
    }

    @PostMapping(SIGNOUT_URL)
    public ResponseEntity<?> logoutUser(HttpServletResponse response) {
        return ResponseEntity.ok(response);
    }
}
```

## OpenID Connect Authentication

### Requirements
- Setup OpenID with Google Cloud Console: If you havent you can follow this guide [Authentication with OpenID
](https://www.linkedin.com/pulse/authentication-withopenid-yi-leng-yao-wivff/)

Set the following environment variables:
```bash
export MONGO_DATABASE_URI=<your-mongo-database-uri>
export JWT_ACCESS_SIGNING_KEY=<your-jwt-access-signing-key>
export JWT_REFRESH_SIGNING_KEY=<your-jwt-refresh-signing-key> 
export GOOGLE_CLIENT_ID=<your-google-client-id>
export GOOGLE_CLIENT_SECRET=<your-google-client-secret>
export OAUTH2_REDIRECT_BASE_URI=<localhost:8080 if developing locally or your-domain>
```

Create the configuration file `SecurityConfig.java`

```java

@Configuration
@EnableWebSecurity
@Import(InnoBridgeSecurityConfig.class)
@EnableMongoRepositories(basePackages = {
        "io.github.innobridge.security.repository",
        <Location of your Mongo Repository>, // eg. "io.yilengyao.jwtauth.repository"
})
public class SecurityConfig implements WebMvcConfigurer {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   UsernamePasswordAuthenticationFilter usernameEmailPasswordAuthenticationFilter,
                                                   UsernameEmailPasswordRegistrationFilter usernameEmailPasswordRegistrationFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   RefreshTokenFilter refreshTokenFilter,
                                                   LogoutFilter logoutFilter,
                                                   CustomOAuth2SuccessHandler customOAuth2SuccessHandler,
                                                   ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers(WHITE_LIST_URL).permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Default to stateless
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Stateful for OAuth2 flows
                        .sessionFixation().none()  // No session fixation protection
                )
                .oauth2Login(oauth2 ->
                        oauth2.clientRegistrationRepository(clientRegistrationRepository)// Ensure OAuth2 login is configured
                                .successHandler(customOAuth2SuccessHandler))
                .addFilterAt(usernameEmailPasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(usernameEmailPasswordRegistrationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(logoutFilter, RefreshTokenFilter.class);
        return http.build();
    }
}
```
The user can login via Google Oauth2 by calling the URL:
- GET `localhost:8080/oauth2/authorization/google` if developing locally
- GET `https://<your-domain>/oauth2/authorization/google` if running in production
Once the user is authenticated, an access token will be returned in the response body,
and a refresh token will be saved in a HttpOnly cookie.

