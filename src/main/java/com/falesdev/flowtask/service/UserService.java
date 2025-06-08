package com.falesdev.flowtask.service;

import com.falesdev.flowtask.domain.dto.UserDto;
import com.falesdev.flowtask.domain.dto.request.CreateUserRequestDto;
import com.falesdev.flowtask.domain.dto.request.UpdateUserRequestDto;

import java.util.List;
import java.util.UUID;

public interface UserService {
    List<UserDto> getAllUsers();
    UserDto getUserById(UUID id);
    UserDto createUser(CreateUserRequestDto userDto);
    UserDto updateUser(UUID id, UpdateUserRequestDto userDto);
    void deleteUser(UUID id);
}
