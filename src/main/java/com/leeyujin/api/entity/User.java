package com.leeyujin.api.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * User 엔티티
 * Neon(PostgreSQL)에 저장되는 사용자 정보
 */
@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String provider; // OAuth Provider (google, kakao, naver)

    @Column(nullable = false, name = "provider_id")
    private String providerId; // OAuth Provider의 사용자 ID

    @Column(unique = true)
    private String email; // 이메일

    @Column
    private String nickname; // 닉네임

    @Column(name = "refresh_token")
    private String refreshToken; // Refresh Token

    @Column(name = "refresh_token_expires_at")
    private LocalDateTime refreshTokenExpiresAt; // Refresh Token 만료 시간

    @Column(nullable = false, updatable = false, name = "created_at")
    private LocalDateTime createdAt; // 생성 시간

    @Column(nullable = false, name = "updated_at")
    private LocalDateTime updatedAt; // 수정 시간

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}

