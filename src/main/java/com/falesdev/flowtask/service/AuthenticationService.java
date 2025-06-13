package com.falesdev.flowtask.service;

import com.falesdev.flowtask.domain.dto.request.RegisterRequest;
import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.dto.response.AuthUserResponse;
import com.falesdev.flowtask.domain.dto.response.MiniOnBoardingRequest;
import com.falesdev.flowtask.domain.dto.response.PasswordResetTokenResponse;
import com.falesdev.flowtask.security.FlowUserDetails;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {
    MiniOnBoardingRequest getStarted();
    AuthResponse authenticate(String email, String password);
    AuthResponse register(RegisterRequest registerRequest);
    void sendPasswordOtp(String email);
    PasswordResetTokenResponse validatePasswordOtp(String email, String otpCode);
    void resetPassword(String resetToken, String newPassword);
    AuthResponse handleGoogleAuth(String idToken);
    UserDetails validateToken(String token);
    AuthUserResponse getUserProfile(FlowUserDetails userDetails);
    AuthResponse handleGithubAuth(String code);
}
