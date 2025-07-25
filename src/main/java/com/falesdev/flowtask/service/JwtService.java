package com.falesdev.flowtask.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;

public interface JwtService {
    Claims parseClaims(String token);
    long getExpirationTime(String token);
    Key getSigningKey();
    String generateAccessToken(UserDetails userDetails);
    String generateRefreshToken(UserDetails userDetails);
    long getJwtExpirationMs();
    long getRefreshExpirationMs();
    String generatePasswordResetToken(String email);
    String validatePasswordResetToken(String token);
}
