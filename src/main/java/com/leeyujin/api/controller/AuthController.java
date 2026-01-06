package com.leeyujin.api.controller;

import com.leeyujin.api.entity.User;
import com.leeyujin.api.oauthservice.common.jwt.JwtTokenProvider;
import com.leeyujin.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 인증 관련 컨트롤러
 * Access/Refresh 토큰 재발급 및 로그아웃 처리
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    @Value("${cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${cookie.same-site:Lax}")
    private String cookieSameSite;

    @Value("${cookie.domain:.leeyujin.kr}")
    private String cookieDomain;

    /**
     * Refresh Token으로 Access Token 재발급 (회전 포함)
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("success", false, "message", "Refresh token not found"));
        }

        try {
            // Refresh Token 검증
            if (!jwtTokenProvider.validateToken(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "Invalid refresh token"));
            }

            // Refresh Token 타입 확인
            String tokenType = jwtTokenProvider.getTokenType(refreshToken);
            if (!"refresh".equals(tokenType)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "Token is not a refresh token"));
            }

            // 사용자 ID 추출
            Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
            String jti = jwtTokenProvider.getJtiFromToken(refreshToken);

            // DB에서 사용자 조회 및 Refresh Token 검증
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "User not found"));
            }

            User user = userOpt.get();

            // DB에 저장된 Refresh Token과 일치하는지 확인
            if (user.getRefreshToken() == null || !user.getRefreshToken().equals(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "Refresh token mismatch"));
            }

            // 만료 시간 확인
            if (user.getRefreshTokenExpiresAt() != null 
                    && user.getRefreshTokenExpiresAt().isBefore(LocalDateTime.now())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "Refresh token expired"));
            }

            // 새 Access Token 생성
            String newAccessToken = jwtTokenProvider.generateAccessToken(
                    userId,
                    user.getProvider(),
                    user.getEmail() != null ? user.getEmail() : "",
                    user.getNickname() != null ? user.getNickname() : "");

            // Refresh Token 회전 (새로운 Refresh Token 생성)
            String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);
            String newJti = jwtTokenProvider.getJtiFromToken(newRefreshToken);

            // 기존 Refresh Token 폐기하고 새 것으로 교체
            user.setRefreshToken(newRefreshToken);
            user.setRefreshTokenExpiresAt(LocalDateTime.now().plusDays(14));
            userRepository.save(user);

            System.out.println("[AuthController] 토큰 재발급 완료 - User ID: " + userId);
            System.out.println("  - 기존 jti: " + jti);
            System.out.println("  - 새 jti: " + newJti);

            // 새 Refresh Token을 쿠키로 설정
            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", newRefreshToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .sameSite(cookieSameSite)
                    .domain(cookieDomain)
                    .path("/api/auth/refresh")
                    .maxAge(14 * 24 * 60 * 60) // 14일
                    .build();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("access_token", newAccessToken);
            response.put("message", "Tokens refreshed successfully");

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                    .body(response);

        } catch (Exception e) {
            System.err.println("[AuthController] 토큰 재발급 실패: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "Token refresh failed: " + e.getMessage()));
        }
    }

    /**
     * 로그아웃
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {

        try {
            if (refreshToken != null && !refreshToken.isEmpty()) {
                // Refresh Token 검증 및 사용자 조회
                if (jwtTokenProvider.validateToken(refreshToken)) {
                    Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
                    Optional<User> userOpt = userRepository.findById(userId);
                    
                    if (userOpt.isPresent()) {
                        User user = userOpt.get();
                        // Refresh Token 폐기
                        user.setRefreshToken(null);
                        user.setRefreshTokenExpiresAt(null);
                        userRepository.save(user);
                        System.out.println("[AuthController] 로그아웃 완료 - User ID: " + userId);
                    }
                }
            }

            // 쿠키 삭제
            ResponseCookie deleteCookie = ResponseCookie.from("refresh_token", "")
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .sameSite(cookieSameSite)
                    .domain(cookieDomain)
                    .path("/api/auth/refresh")
                    .maxAge(0) // 즉시 만료
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
                    .body(Map.of("success", true, "message", "Logged out successfully"));

        } catch (Exception e) {
            System.err.println("[AuthController] 로그아웃 실패: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "Logout failed: " + e.getMessage()));
        }
    }
}

