package com.leeyujin.api.oauthservice.user.oauth;

import org.springframework.stereotype.Service;

/**
 * User OAuth 통합 서비스
 * OAuthClientFactory를 통해 provider를 선택하고 OAuth 인증을 처리합니다.
 */
@Service
public class UserOAuthService {

    private final OAuthClientFactory oauthClientFactory;

    public UserOAuthService(OAuthClientFactory oauthClientFactory) {
        this.oauthClientFactory = oauthClientFactory;
    }

    /**
     * 인가 코드로 액세스 토큰 요청
     * @param provider provider 이름 (google, kakao, naver)
     * @param code 인가 코드
     * @param state CSRF 방지를 위한 state 값 (선택적)
     * @return 액세스 토큰이 포함된 응답 객체
     */
    public OAuthTokenResponse getAccessToken(String provider, String code, String state) {
        OAuthClient client = oauthClientFactory.getClient(provider);
        return client.getAccessToken(code, state);
    }

    /**
     * 액세스 토큰으로 사용자 정보 요청
     * @param provider provider 이름 (google, kakao, naver)
     * @param accessToken 액세스 토큰
     * @return 사용자 정보가 포함된 응답 객체
     */
    public OAuthUserInfo getUserInfo(String provider, String accessToken) {
        OAuthClient client = oauthClientFactory.getClient(provider);
        return client.getUserInfo(accessToken);
    }

    /**
     * 인가 URL 생성
     * @param provider provider 이름 (google, kakao, naver)
     * @return 인가 URL
     */
    public String getAuthUrl(String provider) {
        OAuthClient client = oauthClientFactory.getClient(provider);
        return client.getAuthUrl();
    }
}

