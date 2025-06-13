package com.falesdev.flowtask.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record GithubAuthRequest(
        @NotBlank(message = "AccessToken is required")
        String code
) {
}
