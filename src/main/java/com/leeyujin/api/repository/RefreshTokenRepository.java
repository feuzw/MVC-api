package com.leeyujin.api.repository;

import com.leeyujin.api.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Refresh Token 리포지토리
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * 토큰으로 Refresh Token 조회
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * 사용자 ID와 Provider로 Refresh Token 조회
     */
    Optional<RefreshToken> findByUserIdAndProvider(String userId, String provider);

    /**
     * 만료된 토큰 삭제
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * 특정 사용자의 토큰 삭제
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId = :userId AND rt.provider = :provider")
    void deleteByUserIdAndProvider(@Param("userId") String userId, @Param("provider") String provider);
}

