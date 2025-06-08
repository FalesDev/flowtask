package com.falesdev.flowtask.config;

import com.falesdev.flowtask.domain.RegisterType;
import com.falesdev.flowtask.domain.entity.Role;
import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.repository.postgres.RoleRepository;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {

    @Value("${imagekit.url-endpoint}")
    private String imagekitUrlEndpoint;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    @Transactional
    public CommandLineRunner initializeData() {
        return args -> {
            Role userRole = createRoleIfNotFound("USER");
            Role adminRole = createRoleIfNotFound("ADMIN");

            createUserIfNotFound(
                    "admin.test",
                    "admin@test.com",
                    "Admin User",
                    "adminpassword",
                    adminRole);
            createUserIfNotFound(
                    "user.test",
                    "user@test.com",
                    "Test User",
                    "password",
                    userRole);
        };
    }

    private Role createRoleIfNotFound(String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    log.info("Creating rol: {}", name);
                    return roleRepository.save(
                            Role.builder()
                                    .name(name)
                                    .build()
                    );
                });
    }

    private void createUserIfNotFound(String userName, String email, String fullName,
                                      String rawPassword, Role role) {
        userRepository.findByEmail(email).orElseGet(() -> {
            log.info("Creating user: {}", email);
            return userRepository.save(
                    User.builder()
                            .username(userName)
                            .email(email)
                            .fullName(fullName)
                            .password(passwordEncoder.encode(rawPassword))
                            .role(role)
                            .registerType(RegisterType.LOCAL)
                            .imageURL(imagekitUrlEndpoint + "/avatar-default.svg")
                            .build()
            );
        });
    }
}
