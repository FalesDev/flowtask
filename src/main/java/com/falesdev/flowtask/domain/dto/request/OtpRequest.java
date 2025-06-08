package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record OtpRequest (
        @NotBlank(message = "Target is required")
        @Email(message = "Email should be valid")
        String email
){
}
