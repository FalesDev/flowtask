package com.falesdev.flowtask.domain.dto;

import com.falesdev.flowtask.domain.RegisterType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private UUID id;
    private String username;
    private String email;
    private String password;
    private String fullName;
    private RoleDto role;
    private String imageURL;
    private RegisterType registerType;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
