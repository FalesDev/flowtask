package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.domain.RegisterType;
import com.falesdev.flowtask.domain.dto.request.RegisterRequest;
import com.falesdev.flowtask.domain.dto.response.AuthResponse;
import com.falesdev.flowtask.domain.dto.response.AuthUserResponse;
import com.falesdev.flowtask.domain.dto.response.MiniOnBoardingRequest;
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
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    @Value("${imagekit.url-endpoint}")
    private String imagekitUrlEndpoint;

    @Value("${github.client.android.id}")
    private String githubClientId;

    @Value("${github.secret.android.id}")
    private String githubClientSecret;

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
    @Transactional(readOnly = true)
    public MiniOnBoardingRequest getStarted() {
        String imageUrl = imagekitUrlEndpoint + "/get-started.png";
        List<String> functions = Arrays.asList("Crear tarea", "Establecer recordatorios", "Seguimiento del progreso");
        return MiniOnBoardingRequest.builder()
                .started("Empezar")
                .functions(functions)
                .imageUrl(imageUrl)
                .build();
    }

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

    @Override
    @Transactional
    public AuthResponse handleGithubAuth(String code) {
        String accessToken = exchangeCodeForAccessToken(code);
        Map<String, Object> userAttributes = getGithubUserInfo(accessToken);
        User user = oAuth2UserManagementService.createOrUpdateUserFromGithub(userAttributes);
        return generateAuthResponse(user);
    }

    private String exchangeCodeForAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", githubClientId);
        requestBody.add("client_secret", githubClientSecret);
        requestBody.add("code", code);
        requestBody.add("redirect_uri", "com.dadky.noteapp://callback");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                "https://github.com/login/oauth/access_token",
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<Map<String, Object>>() {}
        );

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new AuthenticationException("Failed to exchange code for access token");
        }
    }

    public Map<String, Object> getGithubUserInfo(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        HttpEntity<?> entity = new HttpEntity<>(headers);

        // 1. Obtener perfil
        ResponseEntity<Map<String, Object>> userResponse = restTemplate.exchange(
                "https://api.github.com/user",
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {}
        );

        if (userResponse.getStatusCode() != HttpStatus.OK || userResponse.getBody() == null) {
            throw new AuthenticationException("Invalid GitHub access token");
        }

        Map<String, Object> userAttributes = userResponse.getBody();

        // 2. Obtener email si no viene directo
        if (userAttributes.get("email") == null) {
            ResponseEntity<List<Map<String, Object>>> emailsResponse = restTemplate.exchange(
                    "https://api.github.com/user/emails",
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            if (emailsResponse.getStatusCode() == HttpStatus.OK && emailsResponse.getBody() != null) {
                for (Map<String, Object> emailEntry : emailsResponse.getBody()) {
                    if (Boolean.TRUE.equals(emailEntry.get("primary")) && Boolean.TRUE.equals(emailEntry.get("verified"))) {
                        userAttributes.put("email", emailEntry.get("email"));
                        break;
                    }
                }
            }
        }

        if (userAttributes.get("email") == null) {
            throw new AuthenticationException("No verified email found in GitHub profile");
        }

        return userAttributes;
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
