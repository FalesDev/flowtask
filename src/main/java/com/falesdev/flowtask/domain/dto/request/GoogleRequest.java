package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record GoogleRequest(
        @NotBlank(message = "IdToken is required")
        String idToken
) {
}
