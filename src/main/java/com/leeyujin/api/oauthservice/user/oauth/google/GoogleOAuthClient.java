package com.leeyujin.api.oauthservice.user.oauth.google;

import com.leeyujin.api.oauthservice.user.oauth.OAuthClient;
import com.leeyujin.api.oauthservice.user.oauth.OAuthTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.OAuthUserInfo;
import com.leeyujin.api.oauthservice.user.oauth.google.dto.GoogleTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.google.dto.GoogleUserinfo;
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
public class GoogleOAuthClient implements OAuthClient {

    private final RestTemplate restTemplate;

    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.client-secret}")
    private String clientSecret;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    @Value("${google.auth-url:https://accounts.google.com/o/oauth2/v2/auth}")
    private String authUrl;

    @Value("${google.token-url:https://oauth2.googleapis.com/token}")
    private String tokenUrl;

    @Value("${google.api-url:https://www.googleapis.com/oauth2/v2}")
    private String apiUrl;

    public GoogleOAuthClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuthTokenResponse getAccessToken(String code, String state) {
        System.out.println("[GoogleOAuthClient] 구글 토큰 엔드포인트 호출: " + tokenUrl);
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("redirect_uri", redirectUri);
        formData.add("code", code);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);
        
        GoogleTokenResponse response = restTemplate.postForObject(
                tokenUrl,
                request,
                GoogleTokenResponse.class
        );

        if (response != null && response.getAccessToken() != null) {
            System.out.println("[GoogleOAuthClient] 액세스 토큰 수신 성공");
        } else {
            System.out.println("[GoogleOAuthClient] 액세스 토큰 수신 실패");
        }

        return response;
    }

    @Override
    public OAuthUserInfo getUserInfo(String accessToken) {
        System.out.println("[GoogleOAuthClient] 구글 사용자 정보 API 호출: " + apiUrl + "/userinfo");
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        GoogleUserinfo userInfo = restTemplate.exchange(
                apiUrl + "/userinfo",
                HttpMethod.GET,
                entity,
                GoogleUserinfo.class
        ).getBody();

        if (userInfo != null && userInfo.getId() != null) {
            System.out.println("[GoogleOAuthClient] 사용자 정보 수신 성공 - ID: " + userInfo.getId());
        } else {
            System.out.println("[GoogleOAuthClient] 사용자 정보 수신 실패");
        }

        return new GoogleUserInfoAdapter(userInfo);
    }

    @Override
    public String getProviderName() {
        return "google";
    }

    @Override
    public String getAuthUrl() {
        try {
            System.out.println("[GoogleOAuthClient] 리다이렉트 URI: " + redirectUri);
            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
            System.out.println("[GoogleOAuthClient] 인코딩된 리다이렉트 URI: " + encodedRedirectUri);
            String authUrlWithParams = authUrl +
                    "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                    "&redirect_uri=" + encodedRedirectUri +
                    "&response_type=code" +
                    "&scope=openid email profile";
            System.out.println("[GoogleOAuthClient] 생성된 인가 URL: " + authUrlWithParams);
            return authUrlWithParams;
        } catch (Exception e) {
            throw new RuntimeException("인가 URL 생성 실패", e);
        }
    }

    /**
     * GoogleUserinfo를 OAuthUserInfo 인터페이스로 변환하는 어댑터
     */
    private static class GoogleUserInfoAdapter implements OAuthUserInfo {
        private final GoogleUserinfo userinfo;

        public GoogleUserInfoAdapter(GoogleUserinfo userinfo) {
            this.userinfo = userinfo;
        }

        @Override
        public String getId() {
            return userinfo != null ? userinfo.getId() : null;
        }

        @Override
        public String getEmail() {
            return userinfo != null ? userinfo.getEmail() : null;
        }

        @Override
        public String getNickname() {
            if (userinfo == null) return null;
            String name = userinfo.getName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
            String email = userinfo.getEmail();
            if (email != null && !email.isEmpty()) {
                return email.split("@")[0];
            }
            return "구글사용자_" + userinfo.getId();
        }

        @Override
        public String getName() {
            return userinfo != null ? userinfo.getName() : null;
        }
    }
}

