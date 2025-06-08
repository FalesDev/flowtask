package com.falesdev.flowtask.security.service;

import com.falesdev.flowtask.domain.RegisterType;
import com.falesdev.flowtask.domain.entity.Role;
import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.repository.postgres.RoleRepository;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import com.falesdev.flowtask.service.ImageKitService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserManagementService {

    @Value("${imagekit.url-endpoint}")
    private String imagekitUrlEndpoint;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ImageKitService imageKitService;

    private final RestTemplate restTemplate;

    public User createOrUpdateUserFromGoogle(GoogleIdToken.Payload payload) {
        String email = payload.getEmail();
        String fullName = (String) payload.get("name");
        String googlePicture = (String) payload.get("picture");
        String username = generateUniqueUsername(fullName);

        return userRepository.findByEmail(email)
                .map(existingUser -> updateExistingUser(
                        existingUser,
                        fullName,
                        googlePicture,
                        username
                ))
                .orElseGet(() -> createNewUser(
                        email,
                        fullName,
                        googlePicture,
                        username
                ));
    }

    private User createNewUser(String email, String fullName, String googlePicture, String username) {
        String cdnUrl = downloadAndStoreProfileImage(googlePicture, email);

        Role defaultRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new EntityNotFoundException("Role USER not found"));

        return userRepository.save(
                User.builder()
                        .email(email)
                        .password(null)
                        .fullName(fullName)
                        .username(username)
                        .role(defaultRole)
                        .imageURL(cdnUrl)
                        .registerType(RegisterType.GOOGLE)
                        .build()
        );
    }

    private User updateExistingUser(User existingUser, String fullName, String googlePicture, String username) {
        existingUser.setFullName(fullName);

        if (existingUser.getUsername() == null || existingUser.getUsername().isBlank()) {
            existingUser.setUsername(username);
        }

        if (!isImageFromOurCDN(existingUser.getImageURL())) {
            String cdnUrl = downloadAndStoreProfileImage(googlePicture, existingUser.getEmail());
            existingUser.setImageURL(cdnUrl);
            log.info("Image migrated to CDN for existing user: {}", existingUser.getEmail());
        }

        return userRepository.save(existingUser);
    }

    private String generateUniqueUsername(String fullName) {
        String base = (fullName == null || fullName.trim().isEmpty())
                ? "user"
                : fullName.trim().toLowerCase();

        String cleanedName = base
                .replaceAll("[^a-z0-9]+", ".")
                .replaceAll("^[.]|[.]$", "");

        int maxBaseLength = 25 - 7;
        if (cleanedName.length() > maxBaseLength) {
            cleanedName = cleanedName.substring(0, maxBaseLength);
        }

        String shortHash;
        String username;
        do {
            shortHash = UUID.randomUUID().toString()
                    .replace("-", "")
                    .substring(0, 6);
            username = cleanedName + "." + shortHash;
        } while (userRepository.existsByUsername(username));

        return username;
    }

    private String downloadAndStoreProfileImage(String imageUrl, String email) {
        if (isImageFromOurCDN(imageUrl)) {
            return imageUrl;
        }

        try {
            ResponseEntity<byte[]> response = restTemplate.exchange(
                    imageUrl,
                    HttpMethod.GET,
                    null,
                    byte[].class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                byte[] imageData = response.getBody();
                String sanitizedEmail = email.replace("@", "_");
                String hash = DigestUtils.md5DigestAsHex(imageData);
                String fileName = "profile_" + sanitizedEmail + "_" + hash + ".jpg";

                return imageKitService.uploadImage(imageData, fileName);
            }
            return imageUrl;
        } catch (Exception e) {
            log.error("Error downloading profile image from Google", e);
            return imageUrl;
        }
    }

    private boolean isImageFromOurCDN(String imageUrl) {
        if (imageUrl == null) return false;
        return imageUrl.startsWith(imagekitUrlEndpoint);
    }
}
