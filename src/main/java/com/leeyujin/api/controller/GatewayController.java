package com.leeyujin.api.controller;

import com.leeyujin.api.oauthservice.user.oauth.google.GoogleController;
import com.leeyujin.api.oauthservice.user.oauth.kakao.KakaoController;
import com.leeyujin.api.oauthservice.user.oauth.naver.NaverController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * API Gateway Controller
 * 
 * 모든 API 요청을 받아서 적절한 컨트롤러로 라우팅하는 중앙 게이트웨이 컨트롤러
 * 
 * 경로 구조:
 * - /api/auth/{provider}/login - 인가 URL 반환 (각 provider 컨트롤러로 라우팅)
 * - /api/auth/{provider}/callback - OAuth 콜백 처리 (각 provider 컨트롤러로 라우팅)
 * - /api/auth/refresh-token - Refresh Token을 httpOnly 쿠키에 저장
 */
@RestController
@RequestMapping("/api")
public class GatewayController {

    @Autowired
    private GoogleController googleController;

    @Autowired
    private KakaoController kakaoController;

    @Autowired
    private NaverController naverController;

    @Value("${FRONTEND_URL:${google.frontend-url:http://localhost:3000}}")
    private String frontendUrl;

    @Value("${cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${cookie.same-site:Lax}")
    private String cookieSameSite;

    /**
     * OAuth 인가 URL 반환 - 게이트웨이 라우팅
     * GET /api/auth/{provider}/login
     * 
     * @param provider - OAuth 제공자 (google, kakao, naver)
     * @return 인가 URL이 포함된 응답
     */
    @GetMapping("/auth/{provider}/login")
    public ResponseEntity<Map<String, Object>> getAuthUrl(@PathVariable String provider) {
        System.out.println("[GatewayController] " + provider + " 인가 URL 요청 - 라우팅 중...");

        // 지원하는 provider인지 확인
        if (!isValidProvider(provider)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", "지원하지 않는 OAuth 제공자입니다: " + provider));
        }

        // 각 provider 컨트롤러로 라우팅
        try {
            switch (provider.toLowerCase()) {
                case "google":
                    return googleController.getAuthUrl();
                case "kakao":
                    return kakaoController.getAuthUrl();
                case "naver":
                    return naverController.getAuthUrl();
                default:
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "success", false,
                            "message", "지원하지 않는 OAuth 제공자입니다: " + provider));
            }
        } catch (Exception e) {
            System.err.println("[GatewayController] [실패] " + provider + " 인가 URL 요청 중 오류: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "인가 URL 생성 실패: " + e.getMessage()));
        }
    }

    /**
     * OAuth 콜백 처리 - 게이트웨이 라우팅
     * GET /api/auth/{provider}/callback?code=xxxxx&state=xxxxx
     * 
     * @param provider - OAuth 제공자 (google, kakao, naver)
     * @param code     - 인가 코드
     * @param state    - CSRF 방지를 위한 state 값 (선택적)
     * @return 프론트엔드로 리다이렉트
     */
    @GetMapping("/auth/{provider}/callback")
    public ResponseEntity<Void> callback(
            @PathVariable String provider,
            @RequestParam String code,
            @RequestParam(required = false) String state) {

        System.out.println("[GatewayController] " + provider + " 콜백 요청 - 라우팅 중...");
        System.out.println("  - Code: " + code);
        if (state != null) {
            System.out.println("  - State: " + state);
        }

        // 지원하는 provider인지 확인
        if (!isValidProvider(provider)) {
            System.err.println("[GatewayController] [실패] 지원하지 않는 OAuth 제공자: " + provider);
            // 에러 처리는 각 컨트롤러에서 처리하므로 여기서는 기본 에러 응답
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        // 각 provider 컨트롤러로 라우팅
        try {
            switch (provider.toLowerCase()) {
                case "google":
                    return googleController.callback(code);
                case "kakao":
                    return kakaoController.callback(code);
                case "naver":
                    return naverController.callback(code, state);
                default:
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
        } catch (Exception e) {
            System.err.println("[GatewayController] [실패] " + provider + " 콜백 처리 중 오류: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Refresh Token을 httpOnly 쿠키에 저장
     * POST /api/auth/refresh-token
     * 
     * @param request - Refresh Token이 포함된 요청 본문
     * @return 성공 여부
     */
    @PostMapping("/auth/refresh-token")
    public ResponseEntity<Map<String, Object>> saveRefreshToken(@RequestBody Map<String, String> request) {
        System.out.println("[GatewayController] Refresh Token 저장 요청");

        try {
            String refreshToken = request.get("refreshToken");

            if (refreshToken == null || refreshToken.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "success", false,
                        "message", "Refresh Token이 제공되지 않았습니다."));
            }

            // Refresh Token을 httpOnly 쿠키에 저장
            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .sameSite(cookieSameSite)
                    .path("/")
                    .maxAge(7 * 24 * 60 * 60) // 7일 (초 단위)
                    .build();

            System.out.println("[GatewayController] [성공] Refresh Token이 httpOnly 쿠키로 저장되었습니다.");

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                    .body(Map.of(
                            "success", true,
                            "message", "Refresh Token이 성공적으로 저장되었습니다."));
        } catch (Exception e) {
            System.err.println("[GatewayController] [실패] Refresh Token 저장 실패: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Refresh Token 저장 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }

    /**
     * 지원하는 OAuth 제공자인지 확인
     */
    private boolean isValidProvider(String provider) {
        return provider != null &&
                (provider.equalsIgnoreCase("google") ||
                        provider.equalsIgnoreCase("kakao") ||
                        provider.equalsIgnoreCase("naver"));
    }
}
