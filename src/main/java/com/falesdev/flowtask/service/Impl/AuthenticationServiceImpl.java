package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.domain.RegisterType;
import com.falesdev.flowtask.domain.dto.request.RegisterRequest;
import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.dto.response.AuthUserResponse;
import com.falesdev.flowtask.domain.dto.response.PasswordResetTokenResponse;
import com.falesdev.flowtask.domain.entity.Role;
import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.domain.redis.Otp;
import com.falesdev.flowtask.exception.AuthenticationException;
import com.falesdev.flowtask.exception.EmailAlreadyExistsException;
import com.falesdev.flowtask.exception.OtpInvalidException;
import com.falesdev.flowtask.exception.TokenValidationException;
import com.falesdev.flowtask.mapper.RoleMapper;
import com.falesdev.flowtask.repository.postgres.RoleRepository;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import com.falesdev.flowtask.repository.redis.OtpRepository;
import com.falesdev.flowtask.security.FlowUserDetails;
import com.falesdev.flowtask.security.service.OAuth2UserManagementService;
import com.falesdev.flowtask.service.AuthenticationService;
import com.falesdev.flowtask.service.EmailService;
import com.falesdev.flowtask.service.JwtService;
import com.falesdev.flowtask.service.RefreshTokenService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    @Value("${imagekit.url-endpoint}")
    private String imagekitUrlEndpoint;

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final RefreshTokenService refreshTokenService;
    private final RoleMapper roleMapper;
    private final OAuth2UserManagementService oAuth2UserManagementService;
    private final GoogleIdTokenVerifier verifier;
    private final OtpRepository otpRepository;

    @Override
    @Transactional
    public AuthResponse authenticate(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email,password)
        );

        FlowUserDetails userDetails = (FlowUserDetails) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = refreshTokenService.createRefreshToken(userDetails.getId()).getToken();
        long expiresIn = jwtService.getExpirationTime(accessToken) / 1000;

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .build();
    }

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest registerRequest) {
        if (userRepository.existsByEmailIgnoreCase(registerRequest.email())) {
            throw new EmailAlreadyExistsException("Email already registered");
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new EntityNotFoundException("Role USER not found"));

        String imageDefault = imagekitUrlEndpoint + "/avatar-default.svg";

        User newUser = User.builder()
                .username(registerRequest.username())
                .email(registerRequest.email())
                .password(passwordEncoder.encode(registerRequest.password()))
                .fullName(registerRequest.fullName())
                .role(userRole)
                .imageURL(imageDefault)
                .registerType(RegisterType.LOCAL)
                .build();

        userRepository.save(newUser);

        emailService.sendWelcomeEmail(newUser.getEmail(), newUser.getFullName());
        return generateAuthResponse(newUser);
    }

    @Override
    @Transactional
    public void sendPasswordOtp(String email) {
        String otpCode = generateOtp();
        otpRepository.save(new Otp(
                otpCode,
                email
        ));
        emailService.sendOtpEmail(email, otpCode);
    }

    @Override
    @Transactional
    public PasswordResetTokenResponse validatePasswordOtp(String email, String otpCode) {
        validateGlobalOtp(otpCode, email);
        userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return PasswordResetTokenResponse.builder()
                .resetToken(jwtService.generatePasswordResetToken(email))
                .build();
    }

    @Override
    @Transactional
    public void resetPassword(String resetToken, String newPassword) {
        String email = jwtService.validatePasswordResetToken(resetToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        emailService.sendPasswordChangedNotification(user.getEmail(), user.getFullName());
    }

    @Override
    @Transactional
    public AuthResponse handleGoogleAuth(String idToken) {
        GoogleIdToken.Payload payload = validateIdToken(idToken);
        User user = oAuth2UserManagementService.createOrUpdateUserFromGoogle(payload);
        return generateAuthResponse(user);
    }

    @Override
    public UserDetails validateToken(String token) {
        try {
            final Claims claims = jwtService.parseClaims(token);
            final String username = claims.getSubject();

            return userDetailsService.loadUserByUsername(username);
        } catch (ExpiredJwtException ex) {
            throw new TokenValidationException("Token expired");
        } catch (JwtException | UsernameNotFoundException ex) {
            throw new TokenValidationException("Invalid token: " + ex.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public AuthUserResponse getUserProfile(FlowUserDetails userDetails) {
        User user = userDetails.getUser();
        return new AuthUserResponse(
                userDetails.getId(),
                user.getUsername(),
                user.getFullName(),
                user.getEmail(),
                roleMapper.toDto(user.getRole()),
                user.getImageURL()
        );
    }

    private GoogleIdToken.Payload validateIdToken(String idToken) {
        try {
            GoogleIdToken idTokenObj = verifier.verify(idToken);
            if (idTokenObj == null) throw new AuthenticationException("Invalid token");

            GoogleIdToken.Payload payload = idTokenObj.getPayload();

            if (!payload.getIssuer().equals("https://accounts.google.com")
                    && !payload.getIssuer().equals("accounts.google.com")) {
                throw new AuthenticationException("Invalid token issuer");
            }
            return payload;
        } catch (GeneralSecurityException | IOException e) {
            throw new AuthenticationException("Token validation failed", e);
        }
    }

    private AuthResponse generateAuthResponse(User user) {
        FlowUserDetails userDetails = new FlowUserDetails(user);
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = refreshTokenService.createRefreshToken(user.getId()).getToken();
        long expiresIn = jwtService.getExpirationTime(accessToken) / 1000;

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .build();
    }

    private String generateOtp() {
        return String.format("%06d", new SecureRandom().nextInt(999999));
    }

    private void validateGlobalOtp(String otpCode, String email) {
        Otp otp = otpRepository.findById(email)
                .orElseThrow(() -> new OtpInvalidException("OTP expired"));

        if (!otp.getCode().equals(otpCode)) {
            throw new OtpInvalidException("OTP newPassword incorrect");
        }

        otpRepository.deleteById(otp.getKey());
    }
}
