package com.leeyujin.api.oauthservice.user.oauth;

/**
 * OAuth 사용자 정보 공통 인터페이스
 */
public interface OAuthUserInfo {
    String getId();
    String getEmail();
    String getNickname();
    String getName();
}

