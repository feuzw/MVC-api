package com.leeyujin.api.oauthservice.user.oauth.naver;

import com.leeyujin.api.oauthservice.user.oauth.OAuthTokenResponse;
import com.leeyujin.api.oauthservice.user.oauth.OAuthUserInfo;
import com.leeyujin.api.oauthservice.user.oauth.UserOAuthService;
import com.leeyujin.api.oauthservice.common.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Naver OAuth 서비스 컴포넌트
 * 
 * GatewayController를 통해 /api/auth/naver 경로로 요청이 라우팅됩니다.
 * 실제 OAuth 로직은 이 컴포넌트에서 처리합니다.
 * 
 * 주의: @Component로 변경하여 직접 HTTP 매핑을 하지 않고,
 * GatewayController를 통해서만 접근 가능하도록 했습니다.
 */
@Component
public class NaverController {

    @Autowired
    private UserOAuthService userOAuthService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Value("${naver.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Value("${cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${cookie.same-site:Lax}")
    private String cookieSameSite;

    /**
     * 네이버 인가 코드로 로그인 처리 (콜백 엔드포인트)
     * GatewayController를 통해 /api/auth/naver/callback?code=xxxxx&state=xxxxx로 접근
     * 
     * 플로우:
     * 1. 네이버에서 인가 코드(code) 및 state 수신
     * 2. 네이버 API로 access token 요청
     * 3. 네이버 API로 사용자 정보 요청
     * 4. JWT 토큰 생성
     * 5. HttpOnly + Secure 쿠키로 JWT 설정
     * 6. 프론트엔드로 302 Redirect
     */
    public ResponseEntity<Void> callback(String code, String state) {
        System.out.println("========================================");
        System.out.println("[네이버 로그인 시작] 인가 코드 수신: " + code);
        System.out.println("  - State: " + (state != null ? state : "없음"));
        System.out.println("========================================");

        try {
            // 1. 인가 코드로 액세스 토큰 요청
            System.out.println("[1단계] 인가 코드로 액세스 토큰 요청 중...");
            OAuthTokenResponse tokenResponse = userOAuthService.getAccessToken("naver", code, state != null ? state : "");

            if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
                System.out.println("[실패] 액세스 토큰 발급 실패");
                // 에러 발생 시 프론트엔드로 리다이렉트
                String errorUrl = frontendUrl + "/?error=" +
                        URLEncoder.encode("액세스 토큰 발급 실패", StandardCharsets.UTF_8);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, errorUrl)
                        .build();
            }

            String accessToken = tokenResponse.getAccessToken();
            String refreshToken = tokenResponse.getRefreshToken();
            
            System.out.println(
                    "[성공] 액세스 토큰 발급 완료: "
                            + accessToken.substring(0, Math.min(20, accessToken.length()))
                            + "...");
            
            // Refresh Token 로그 출력 (임시 디버깅용)
            if (refreshToken != null && !refreshToken.isEmpty()) {
                System.out.println("[성공] 리프레시 토큰 발급 완료: "
                        + refreshToken.substring(0, Math.min(30, refreshToken.length())) + "...");
            } else {
                System.out.println("[⚠️ 경고] 리프레시 토큰이 발급되지 않았습니다.");
            }

            // 2. 액세스 토큰으로 사용자 정보 요청
            System.out.println("[2단계] 액세스 토큰으로 사용자 정보 요청 중...");
            OAuthUserInfo userInfo = userOAuthService.getUserInfo("naver", accessToken);

            if (userInfo == null || userInfo.getId() == null) {
                System.out.println("[실패] 사용자 정보 조회 실패");
                // 에러 발생 시 프론트엔드로 리다이렉트
                String errorUrl = frontendUrl + "/?error=" +
                        URLEncoder.encode("사용자 정보 조회 실패", StandardCharsets.UTF_8);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, errorUrl)
                        .build();
            }

            System.out.println("[성공] 사용자 정보 조회 완료 - 네이버 ID: " + userInfo.getId());

            // 3. 사용자 정보 파싱
            System.out.println("[3단계] 사용자 정보 파싱 중...");
            String naverId = userInfo.getId();
            String email = userInfo.getEmail();
            String nickname = userInfo.getNickname();

            // 닉네임이 없으면 이름 또는 이메일 사용
            if (nickname == null || nickname.isEmpty()) {
                String name = userInfo.getName();
                if (name != null && !name.isEmpty()) {
                    nickname = name;
                } else if (email != null && !email.isEmpty()) {
                    nickname = email.split("@")[0];
                } else {
                    nickname = "네이버사용자_" + naverId;
                }
            }

            System.out.println(
                    "[파싱 완료] 네이버 ID: " + naverId + ", 닉네임: " + nickname + ", 이메일: "
                            + (email != null ? email : "없음"));

            // 4. JWT 토큰 생성 (네이버 ID를 Long으로 변환 시도, 실패 시 해시값 사용)
            System.out.println("[4단계] JWT 토큰 생성 중...");
            Long userId;
            try {
                userId = Long.parseLong(naverId);
            } catch (NumberFormatException e) {
                // 네이버 ID가 숫자가 아닌 경우 해시값 사용
                userId = (long) naverId.hashCode();
            }

            String jwtToken = jwtTokenProvider.generateToken(
                    userId,
                    "naver",
                    email != null ? email : "",
                    nickname);
            System.out.println("[성공] JWT 토큰 생성 완료: "
                    + jwtToken.substring(0, Math.min(30, jwtToken.length())) + "...");

            // 5. HttpOnly + Secure 쿠키 생성
            System.out.println("[5단계] 보안 쿠키 생성 중...");

            // 쿠키 설정: HttpOnly, Secure, SameSite
            // HttpOnly: JavaScript 접근 불가 (XSS 공격 방지)
            // Secure: HTTPS에서만 전송 (프로덕션: true, 개발: false)
            // SameSite: CSRF 공격 방지 (Lax: 같은 사이트, None: 다른 도메인 허용)
            ResponseCookie cookie = ResponseCookie.from("token", jwtToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .sameSite(cookieSameSite)
                    .path("/")
                    .maxAge(86400) // 24시간 (초 단위)
                    .build();

            // 프론트엔드 리다이렉트 URL 생성
            String redirectUrl = frontendUrl + "/auth/naver/callback?provider=naver";

            System.out.println("========================================");
            System.out.println("[네이버 로그인 성공]");
            System.out.println("  - 네이버 ID: " + naverId);
            System.out.println("  - 닉네임: " + nickname);
            System.out.println("  - 이메일: " + (email != null ? email : "없음"));
            System.out.println("  - JWT 토큰: " + jwtToken.substring(0, Math.min(50, jwtToken.length()))
                    + "...");
            System.out.println("  - 리다이렉트 URL: " + redirectUrl);
            System.out.println("  - 쿠키 설정: HttpOnly=true, Secure=" + cookieSecure + ", SameSite="
                    + cookieSameSite);
            System.out.println("========================================");

            // 302 Redirect with HttpOnly Cookie
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, redirectUrl)
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .build();

        } catch (Exception e) {
            System.err.println("========================================");
            System.err.println("[네이버 로그인 실패]");
            System.err.println("오류 메시지: " + e.getMessage());
            System.err.println("========================================");
            e.printStackTrace();

            // 에러 발생 시 프론트엔드로 리다이렉트
            String errorUrl = frontendUrl + "/?error=" +
                    URLEncoder.encode("네이버 로그인 처리 중 오류가 발생했습니다: " + e.getMessage(),
                            StandardCharsets.UTF_8);

            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, errorUrl)
                    .build();
        }
    }

    /**
     * 네이버 인가 URL 반환
     * GatewayController를 통해 /api/auth/naver/login로 접근
     */
    public ResponseEntity<Map<String, Object>> getAuthUrl() {
        System.out.println("[네이버 인가 URL 요청]");
        try {
            String authUrlWithParams = userOAuthService.getAuthUrl("naver");

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("authUrl", authUrlWithParams);

            System.out.println("[성공] 네이버 인가 URL 생성 완료: " + authUrlWithParams);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "message", "인가 URL 생성 실패: " + e.getMessage()));
        }
    }
}

