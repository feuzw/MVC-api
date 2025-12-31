package com.leeyujin.api.oauthservice.user.oauth;

/**
 * OAuth Provider 추상화 인터페이스
 * 각 OAuth Provider (Google, Kakao, Naver)는 이 인터페이스를 구현합니다.
 */
public interface OAuthClient {
    
    /**
     * 인가 코드로 액세스 토큰 요청
     * @param code 인가 코드
     * @param state CSRF 방지를 위한 state 값 (선택적)
     * @return 액세스 토큰이 포함된 응답 객체
     */
    OAuthTokenResponse getAccessToken(String code, String state);
    
    /**
     * 액세스 토큰으로 사용자 정보 요청
     * @param accessToken 액세스 토큰
     * @return 사용자 정보가 포함된 응답 객체
     */
    OAuthUserInfo getUserInfo(String accessToken);
    
    /**
     * Provider 이름 반환 (google, kakao, naver)
     * @return provider 이름
     */
    String getProviderName();
    
    /**
     * 인가 URL 생성
     * @return 인가 URL
     */
    String getAuthUrl();
}

