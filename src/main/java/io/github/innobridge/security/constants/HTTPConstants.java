package io.github.innobridge.security.constants;

import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.http.HttpServletRequest;

public class HTTPConstants {
    // Url endpoints
    public static final String PUBLIC_URL = "/public/**";
    public static final String SWAGGER_UI_URL = "/swagger-ui/**";
    public static final String SWAGGER_RESOURCES_URL = "/swagger-resources/";
    public static final String SWAGGER_RESOURCES_ALL_URL = "/swagger-resources/**";
    public static final String API_DOCS_URL = "/v3/api-docs";
    public static final String API_DOCS_ALL_URL = "/v3/api-docs/**";
    public static final String SIGNIN_URL = "/auth/signin";
    public static final String SIGNUP_URL = "/auth/signup";
    public static final String SIGNOUT_URL = "/auth/signout";
    public static final String REFRESH_TOKEN_URL = "/auth/refresh";
    public static final String CONTACTS_URL = "/contacts";

    public static final String EXCHANGE_URL = "/exchange";
    public static final String ACCOUNT_URL = "/account";
    public static final String TRANSACTION_URL = "/transaction";
    public static final String PROFILE_URL = "/profile";

    public static final String OAUTH2_URLS = "/oauth2/**";
    public static final String OAUTH2_BASE_URI = "/oauth2/";
    public static final String LOGIN_OAUTH2_URL = "/login/oauth2/**";
    public static final String OAUTH2_SUCCESS_URL = "/oauth2/success";
    public static final String OAUTH2_FAILURE_URL = "/oauth2/failure";
    public static final String[] WHITE_LIST_URL = {
            PUBLIC_URL,
            SWAGGER_UI_URL,
            SWAGGER_RESOURCES_URL,
            SWAGGER_RESOURCES_ALL_URL,
            API_DOCS_URL,
            API_DOCS_ALL_URL,
            SIGNUP_URL,
            OAUTH2_URLS,
            LOGIN_OAUTH2_URL
    };

    public static final String GOOGLE_AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth";
    public static final String GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";
    public static final String GOOGLE_USER_INFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo";
    public static final String GOOGLE_JWK_SET_URI = "https://www.googleapis.com/oauth2/v3/certs";
    public static final String GOOGLE_REDIRECT_URI_TEMPLATE = "/login/oauth2/code/google";
    public static final String GOOGLE_ID = "google";
    public static final String[] GOOGLE_SCOPES = {"openid", "profile", "email"};
    public static final String OAUTH2_USER_NAME_ATTRIBUTE = "sub";
    public static final String GOOGLE_CLIENT_NAME = "Google";

    // Define your matcher to identify OAuth2-related requests
    private static final RequestMatcher OAUTH2_REQUEST_MATCHER = new RequestMatcher() {
        @Override
        public boolean matches(HttpServletRequest request) {
            // Check if the request URI is related to OAuth2 flow
            return request.getRequestURI().contains(OAUTH2_BASE_URI);
        }
    };

    public static final String ACCESS_TOKEN = "access-token";

    public static final String ACCESS_COOKIE = "access-token";
    public static final String REFRESH_COOKIE = "refresh-token";

    public static final String CONTENT_TYPE = "application/json";

    public static final String OK = "200";
    public static final String CREATED = "201";

    public static final String BEARER_ACCESS_TOKEN_SCHEMA = "BearerAccessTokenSchema";
    public static final String BEARER_ACCESS_TOKEN_FORMAT = "JWT";
    public static final String BEARER = "Bearer";
}
