package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.URL;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequestDto {

    @NotBlank(message = "Username is required")
    private String username;

    @Email(message = "Email should be valid")
    @NotBlank(message = "Email is required")
    private String email;

    @Size(min = 8, max = 20, message = "Password must be between {min} and {max} characters")
    @NotBlank(message = "Password is required")
    private String password;

    @NotBlank(message = "FullName is required")
    private String fullName;

    @NotNull(message = "Role is required")
    private UUID roleId;

    @URL(protocol = "https", message = "Must be a valid HTTPS URL")
    private String imageURL;
}
