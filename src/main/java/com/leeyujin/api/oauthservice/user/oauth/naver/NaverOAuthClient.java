package com.leeyujin.api.oauthservice.user.oauth.naver;

import com.leeyujin.api.oauthservice.user.oauth.OAuthClient;
import com.leeyujin.api.oauthservice.user.oauth.OAuthTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.OAuthUserInfo;
import com.leeyujin.api.oauthservice.user.oauth.naver.dto.NaverTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.naver.dto.NaverUserinfo;
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
import java.util.UUID;

@Component
public class NaverOAuthClient implements OAuthClient {

    private final RestTemplate restTemplate;

    @Value("${naver.client-id}")
    private String clientId;

    @Value("${naver.client-secret}")
    private String clientSecret;

    @Value("${naver.redirect-uri}")
    private String redirectUri;

    @Value("${naver.auth-url:https://nid.naver.com/oauth2.0/authorize}")
    private String authUrl;

    @Value("${naver.token-url:https://nid.naver.com/oauth2.0/token}")
    private String tokenUrl;

    @Value("${naver.api-url:https://openapi.naver.com/v1/nid}")
    private String apiUrl;

    public NaverOAuthClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuthTokenResponse getAccessToken(String code, String state) {
        System.out.println("[NaverOAuthClient] 네이버 토큰 엔드포인트 호출: " + tokenUrl);
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("redirect_uri", redirectUri);
        formData.add("code", code);
        formData.add("state", state != null ? state : "");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);
        
        NaverTokenResponse response = restTemplate.postForObject(
                tokenUrl,
                request,
                NaverTokenResponse.class
        );

        if (response != null && response.getAccessToken() != null) {
            System.out.println("[NaverOAuthClient] 액세스 토큰 수신 성공");
        } else {
            System.out.println("[NaverOAuthClient] 액세스 토큰 수신 실패");
            if (response != null && response.getError() != null) {
                System.out.println("[NaverOAuthClient] 에러: " + response.getError() + " - " + response.getErrorDescription());
            }
        }

        return response;
    }

    @Override
    public OAuthUserInfo getUserInfo(String accessToken) {
        System.out.println("[NaverOAuthClient] 네이버 사용자 정보 API 호출: " + apiUrl + "/me");
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        NaverUserinfo userInfo = restTemplate.exchange(
                apiUrl + "/me",
                HttpMethod.GET,
                entity,
                NaverUserinfo.class
        ).getBody();

        if (userInfo != null && userInfo.getResponse() != null && userInfo.getResponse().getId() != null) {
            System.out.println("[NaverOAuthClient] 사용자 정보 수신 성공 - ID: " + userInfo.getResponse().getId());
        } else {
            System.out.println("[NaverOAuthClient] 사용자 정보 수신 실패");
            if (userInfo != null) {
                System.out.println("[NaverOAuthClient] 결과 코드: " + userInfo.getResultcode() + ", 메시지: " + userInfo.getMessage());
            }
        }

        return new NaverUserInfoAdapter(userInfo);
    }

    @Override
    public String getProviderName() {
        return "naver";
    }

    @Override
    public String getAuthUrl() {
        try {
            System.out.println("[NaverOAuthClient] 리다이렉트 URI: " + redirectUri);
            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
            System.out.println("[NaverOAuthClient] 인코딩된 리다이렉트 URI: " + encodedRedirectUri);
            String state = UUID.randomUUID().toString();
            String authUrlWithParams = authUrl +
                    "?response_type=code" +
                    "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                    "&redirect_uri=" + encodedRedirectUri +
                    "&state=" + state;
            System.out.println("[NaverOAuthClient] 생성된 인가 URL (state: " + state + "): " + authUrlWithParams);
            return authUrlWithParams;
        } catch (Exception e) {
            throw new RuntimeException("인가 URL 생성 실패", e);
        }
    }

    /**
     * NaverUserinfo를 OAuthUserInfo 인터페이스로 변환하는 어댑터
     */
    private static class NaverUserInfoAdapter implements OAuthUserInfo {
        private final NaverUserinfo userinfo;

        public NaverUserInfoAdapter(NaverUserinfo userinfo) {
            this.userinfo = userinfo;
        }

        @Override
        public String getId() {
            return userinfo != null && userinfo.getResponse() != null ? userinfo.getResponse().getId() : null;
        }

        @Override
        public String getEmail() {
            return userinfo != null && userinfo.getResponse() != null ? userinfo.getResponse().getEmail() : null;
        }

        @Override
        public String getNickname() {
            if (userinfo == null || userinfo.getResponse() == null) return null;
            String nickname = userinfo.getResponse().getNickname();
            if (nickname != null && !nickname.isEmpty()) {
                return nickname;
            }
            String name = userinfo.getResponse().getName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
            String email = userinfo.getResponse().getEmail();
            if (email != null && !email.isEmpty()) {
                return email.split("@")[0];
            }
            return "네이버사용자_" + userinfo.getResponse().getId();
        }

        @Override
        public String getName() {
            return userinfo != null && userinfo.getResponse() != null ? userinfo.getResponse().getName() : null;
        }
    }
}

