package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record OtpVerificationRequest(
        @NotBlank(message = "Target is required")
        @Email(message = "Email should be valid")
        String email,

        @NotBlank
        @Size(min = 6, max = 6, message = "Code must have 6 characters")
        String code
) {
}
