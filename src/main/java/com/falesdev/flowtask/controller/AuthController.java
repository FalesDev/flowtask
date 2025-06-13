package com.falesdev.flowtask.controller;

import com.falesdev.flowtask.domain.dto.request.*;
import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.dto.response.AuthUserResponse;
import com.falesdev.flowtask.domain.dto.response.MiniOnBoardingRequest;
import com.falesdev.flowtask.domain.dto.response.PasswordResetTokenResponse;
import com.falesdev.flowtask.security.FlowUserDetails;
import com.falesdev.flowtask.service.AuthenticationService;
import com.falesdev.flowtask.service.RefreshTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    @GetMapping(path = "/started")
    public ResponseEntity<MiniOnBoardingRequest> getStarted(){
        return ResponseEntity.ok(authenticationService.getStarted());
    }

    @PostMapping(path = "/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok(authenticationService.authenticate(
                loginRequest.email(),
                loginRequest.password()
        ));
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authenticationService.register(registerRequest));
    }

    @PostMapping("/password/otp")
    public ResponseEntity<Void> sendPasswordOtp(
            @Valid @RequestBody OtpRequest request
    ) {
        authenticationService.sendPasswordOtp(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password/otp/verify")
    public ResponseEntity<PasswordResetTokenResponse> validatePasswordOtp(
            @Valid @RequestBody OtpVerificationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.validatePasswordOtp(
                request.email(),
                request.code()));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody PasswordResetRequest request
    ) {
        authenticationService.resetPassword(
                request.resetToken(),
                request.newPassword()
        );
        return ResponseEntity.ok().build();
    }

    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleAuth(
            @Valid @RequestBody GoogleRequest request
    ) {
        return ResponseEntity.ok(
                authenticationService.handleGoogleAuth(request.idToken())
        );
    }

    @PostMapping("/github")
    public ResponseEntity<AuthResponse> githubAuth(@RequestBody GithubAuthRequest request) {
        return ResponseEntity.ok(authenticationService.handleGithubAuth(request.code()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(refreshTokenService.refreshAccessToken(request.refreshToken()));
    }

    @GetMapping("/me")
    public ResponseEntity<AuthUserResponse> getUserProfile(
            @AuthenticationPrincipal FlowUserDetails userDetails
    ) {
        return ResponseEntity.ok(authenticationService.getUserProfile(userDetails));
    }
}
