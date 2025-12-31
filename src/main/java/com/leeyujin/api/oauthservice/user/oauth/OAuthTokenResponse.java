package com.leeyujin.api.oauthservice.user.oauth;

/**
 * OAuth 토큰 응답 공통 인터페이스
 */
public interface OAuthTokenResponse {
    String getAccessToken();
    String getTokenType();
    String getRefreshToken();
    Integer getExpiresIn();
}

