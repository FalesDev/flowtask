package com.falesdev.flowtask.service;

import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.entity.RefreshToken;

import java.util.UUID;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(UUID userId);
    AuthResponse refreshAccessToken(String refreshToken);
    void validateRefreshToken(String refreshToken);
}
