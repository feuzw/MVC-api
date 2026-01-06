package com.leeyujin.api.oauthservice.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;
    private final long expiration;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration}") long expiration) {
        // Base64로 인코딩된 키를 디코딩하거나, 일반 문자열인 경우 32바이트 이상으로 패딩
        byte[] keyBytes;
        try {
            // Base64 인코딩된 키인지 확인
            byte[] decodedBytes = Base64.getDecoder().decode(secret);
            // Base64 디코딩 성공했지만 32바이트 미만이면 패딩
            if (decodedBytes.length < 32) {
                byte[] paddedBytes = new byte[32];
                System.arraycopy(decodedBytes, 0, paddedBytes, 0, decodedBytes.length);
                for (int i = decodedBytes.length; i < 32; i++) {
                    paddedBytes[i] = decodedBytes[i % decodedBytes.length];
                }
                keyBytes = paddedBytes;
            } else {
                keyBytes = decodedBytes;
            }
        } catch (IllegalArgumentException e) {
            // Base64가 아니면 일반 문자열로 처리
            byte[] originalBytes = secret.getBytes(StandardCharsets.UTF_8);
            // 32바이트(256비트) 이상이 되도록 패딩 (HS256 알고리즘 사용)
            if (originalBytes.length < 32) {
                byte[] paddedBytes = new byte[32];
                System.arraycopy(originalBytes, 0, paddedBytes, 0, originalBytes.length);
                // 나머지 바이트를 원본 바이트로 반복 채움
                for (int i = originalBytes.length; i < 32; i++) {
                    paddedBytes[i] = originalBytes[i % originalBytes.length];
                }
                keyBytes = paddedBytes;
            } else {
                keyBytes = originalBytes;
            }
        }
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.expiration = expiration;
    }

    // Access Token 생성 (짧게, 10분)
    public String generateAccessToken(Long userId, String provider, String email, String nickname) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 10 * 60 * 1000); // 10분

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("provider", provider);
        claims.put("email", email);
        claims.put("nickname", nickname);
        claims.put("typ", "access");

        return Jwts.builder()
                .claims(claims)
                .subject(userId.toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    // Refresh Token 생성 (길게, 14일, jti 포함)
    public String generateRefreshToken(Long userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000L); // 14일
        String jti = UUID.randomUUID().toString(); // 토큰 ID (회전용)

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("typ", "refresh");
        claims.put("jti", jti); // 토큰 회전을 위한 고유 ID

        return Jwts.builder()
                .claims(claims)
                .subject(userId.toString())
                .id(jti)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    // JWT 토큰에서 jti 추출 (Refresh Token 회전용)
    public String getJtiFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.getId();
    }

    // JWT 토큰 타입 확인
    public String getTokenType(String token) {
        Claims claims = parseToken(token);
        return (String) claims.get("typ");
    }

    // 기존 메서드 유지 (하위 호환성)
    public String generateToken(Long userId, String provider, String email, String nickname) {
        return generateAccessToken(userId, provider, email, nickname);
    }

    // JWT 토큰에서 사용자 ID 추출
    public Long getUserIdFromToken(String token) {
        Claims claims = parseToken(token);
        return Long.parseLong(claims.getSubject());
    }

    // JWT 토큰에서 Provider 추출
    public String getProviderFromToken(String token) {
        Claims claims = parseToken(token);
        return (String) claims.get("provider");
    }

    // JWT 토큰 검증
    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // JWT 토큰 파싱
    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}

