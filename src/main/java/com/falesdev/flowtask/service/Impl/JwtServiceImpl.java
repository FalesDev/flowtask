package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.exception.TokenValidationException;
import com.falesdev.flowtask.security.FlowUserDetails;
import com.falesdev.flowtask.service.JwtService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration-ms}")
    private Long jwtExpiryMs;

    @Value("${jwt.refresh-expiration-ms}")
    private Long refreshExpiryMs;

    @Value("${jwt.password-reset-expiration-ms}")
    private Long passwordResetExpiryMs;

    @Override
    public Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature", e);
        }
    }

    @Override
    public long getExpirationTime(String token) {
        Claims claims = parseClaims(token);
        return claims.getExpiration().getTime() - System.currentTimeMillis();
    }

    @Override
    public Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public String generateAccessToken(UserDetails userDetails) {
        FlowUserDetails collegeUser = (FlowUserDetails) userDetails;

        return Jwts.builder()
                .setSubject(collegeUser.getUsername())
                .claim("userId", collegeUser.getId())
                .claim("role", collegeUser.getUser().getRole().getName())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiryMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        FlowUserDetails collegeUser = (FlowUserDetails) userDetails;

        return Jwts.builder()
                .setSubject(collegeUser.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiryMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public long getJwtExpirationMs() {
        return jwtExpiryMs;
    }

    @Override
    public long getRefreshExpirationMs() {
        return refreshExpiryMs;
    }

    @Override
    public String generatePasswordResetToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + passwordResetExpiryMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String validatePasswordResetToken(String token) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();
            return claims.getSubject();
        } catch (ExpiredJwtException ex) {
            throw new TokenValidationException("Token expired");
        } catch (MalformedJwtException | SignatureException ex) {
            throw new TokenValidationException("Invalid token signature");
        } catch (JwtException | IllegalArgumentException ex) {
            throw new TokenValidationException("Invalid token");
        }
    }
}
