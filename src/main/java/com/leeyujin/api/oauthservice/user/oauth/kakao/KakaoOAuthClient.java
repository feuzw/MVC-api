package com.leeyujin.api.oauthservice.user.oauth.kakao;

import com.leeyujin.api.oauthservice.user.oauth.OAuthClient;
import com.leeyujin.api.oauthservice.user.oauth.OAuthTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.OAuthUserInfo;
import com.leeyujin.api.oauthservice.user.oauth.kakao.dto.KakaoTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.kakao.dto.KakaoUserinfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class KakaoOAuthClient implements OAuthClient {

    private final RestTemplate restTemplate;

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.redirect-uri}")
    private String redirectUri;

    @Value("${kakao.auth-url:https://kauth.kakao.com}")
    private String authUrl;

    @Value("${kakao.api-url:https://kapi.kakao.com}")
    private String apiUrl;

    public KakaoOAuthClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuthTokenResponse getAccessToken(String code, String state) {
        System.out.println("[KakaoOAuthClient] 카카오 토큰 엔드포인트 호출: " + authUrl + "/oauth/token");
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("client_id", clientId);
        formData.add("redirect_uri", redirectUri);
        formData.add("code", code);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);
        
        KakaoTokenResponse response = restTemplate.postForObject(
                authUrl + "/oauth/token",
                request,
                KakaoTokenResponse.class
        );

        if (response != null && response.getAccessToken() != null) {
            System.out.println("[KakaoOAuthClient] 액세스 토큰 수신 성공");
        } else {
            System.out.println("[KakaoOAuthClient] 액세스 토큰 수신 실패");
        }

        return response;
    }

    @Override
    public OAuthUserInfo getUserInfo(String accessToken) {
        System.out.println("[KakaoOAuthClient] 카카오 사용자 정보 API 호출: " + apiUrl + "/v2/user/me");
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        KakaoUserinfo userInfo = restTemplate.exchange(
                apiUrl + "/v2/user/me",
                HttpMethod.GET,
                entity,
                KakaoUserinfo.class
        ).getBody();

        if (userInfo != null && userInfo.getId() != null) {
            System.out.println("[KakaoOAuthClient] 사용자 정보 수신 성공 - ID: " + userInfo.getId());
        } else {
            System.out.println("[KakaoOAuthClient] 사용자 정보 수신 실패");
        }

        return new KakaoUserInfoAdapter(userInfo);
    }

    @Override
    public String getProviderName() {
        return "kakao";
    }

    @Override
    public String getAuthUrl() {
        try {
            System.out.println("[KakaoOAuthClient] 리다이렉트 URI: " + redirectUri);
            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
            System.out.println("[KakaoOAuthClient] 인코딩된 리다이렉트 URI: " + encodedRedirectUri);
            String authUrlWithParams = authUrl + "/oauth/authorize" +
                    "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                    "&redirect_uri=" + encodedRedirectUri +
                    "&response_type=code" +
                    "&scope=account_email profile_nickname"; // 카카오 이메일 및 닉네임 권한 요청
            System.out.println("[KakaoOAuthClient] 생성된 인가 URL: " + authUrlWithParams);
            return authUrlWithParams;
        } catch (Exception e) {
            throw new RuntimeException("인가 URL 생성 실패", e);
        }
    }

    /**
     * KakaoUserinfo를 OAuthUserInfo 인터페이스로 변환하는 어댑터
     */
    private static class KakaoUserInfoAdapter implements OAuthUserInfo {
        private final KakaoUserinfo userinfo;

        public KakaoUserInfoAdapter(KakaoUserinfo userinfo) {
            this.userinfo = userinfo;
        }

        @Override
        public String getId() {
            return userinfo != null && userinfo.getId() != null ? userinfo.getId().toString() : null;
        }

        @Override
        public String getEmail() {
            if (userinfo == null || userinfo.getKakaoAccount() == null) {
                return null;
            }
            return userinfo.getKakaoAccount().getEmail();
        }

        @Override
        public String getNickname() {
            if (userinfo == null) return null;
            if (userinfo.getKakaoAccount() != null && userinfo.getKakaoAccount().getProfile() != null) {
                String nickname = userinfo.getKakaoAccount().getProfile().getNickname();
                if (nickname != null && !nickname.isEmpty()) {
                    return nickname;
                }
            }
            return "카카오사용자_" + (userinfo.getId() != null ? userinfo.getId() : "");
        }

        @Override
        public String getName() {
            return getNickname();
        }
    }
}

