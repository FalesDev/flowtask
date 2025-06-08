package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record PasswordResetRequest(
        @NotBlank(message = "ResetToken is required")
        String resetToken,

        @NotBlank(message = "NewPassword is required")
        String newPassword
) {
}
