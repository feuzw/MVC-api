package com.leeyujin.api.repository;

import com.leeyujin.api.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * User 리포지토리
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Provider와 Provider ID로 사용자 조회
     */
    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    /**
     * 이메일로 사용자 조회
     */
    Optional<User> findByEmail(String email);

    /**
     * 만료된 Refresh Token을 가진 사용자들의 토큰 삭제
     */
    @Modifying
    @Query("UPDATE User u SET u.refreshToken = NULL, u.refreshTokenExpiresAt = NULL WHERE u.refreshTokenExpiresAt < :now")
    void clearExpiredRefreshTokens(@Param("now") LocalDateTime now);
}

