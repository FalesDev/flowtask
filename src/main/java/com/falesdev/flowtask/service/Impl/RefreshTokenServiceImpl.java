package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.entity.RefreshToken;
import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.exception.InvalidRefreshTokenException;
import com.falesdev.flowtask.repository.postgres.RefreshTokenRepository;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import com.falesdev.flowtask.security.FlowUserDetails;
import com.falesdev.flowtask.service.JwtService;
import com.falesdev.flowtask.service.RefreshTokenService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public RefreshToken createRefreshToken(UUID userId) {
        refreshTokenRepository.deleteExpiredOrRevokedByUser(userId, Instant.now());

        User user = userRepository.findById(userId).orElseThrow();
        UserDetails userDetails = new FlowUserDetails(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(jwtService.generateRefreshToken(userDetails))
                .expiryDate(Instant.now().plusMillis(jwtService.getRefreshExpirationMs()))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    @Transactional
    public AuthResponse refreshAccessToken(String refreshToken) {
        validateRefreshToken(refreshToken);

        return refreshTokenRepository.findByToken(refreshToken)
                .map(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);

                    User user = userRepository.findById(token.getUserId())
                            .orElseThrow(() -> new EntityNotFoundException("User not found"));

                    UserDetails userDetails = new FlowUserDetails(user);
                    String newAccessToken = jwtService.generateAccessToken(userDetails);
                    String newRefreshToken = jwtService.generateRefreshToken(userDetails);

                    RefreshToken newToken = RefreshToken.builder()
                            .userId(user.getId())
                            .token(newRefreshToken)
                            .expiryDate(Instant.now().plusMillis(jwtService.getRefreshExpirationMs()))
                            .revoked(false)
                            .build();
                    refreshTokenRepository.save(newToken);

                    long expiresIn = jwtService.getJwtExpirationMs() / 1000;

                    return AuthResponse.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(newRefreshToken)
                            .expiresIn(expiresIn)
                            .build();
                })
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));
    }

    @Override
    @Transactional
    public void validateRefreshToken(String refreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));

        if (token.isRevoked() || token.getExpiryDate().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }
    }
}
