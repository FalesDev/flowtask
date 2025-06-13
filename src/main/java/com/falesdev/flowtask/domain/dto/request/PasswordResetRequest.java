package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank(message = "ResetToken is required")
        String resetToken,

        @NotBlank(message = "NewPassword is required")
        @Size(min = 8, max = 20, message = "Password must be between {min} and {max} characters")
        String newPassword
) {
}
