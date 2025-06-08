package com.falesdev.flowtask.domain.dto.response;

import com.falesdev.flowtask.domain.dto.RoleDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthUserResponse {

    private UUID id;
    private String username;
    private String fullName;
    private String email;
    private RoleDto role;
    private String imageURL;
}
