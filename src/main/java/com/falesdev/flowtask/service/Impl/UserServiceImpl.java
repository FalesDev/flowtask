package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.domain.dto.UserDto;
import com.falesdev.flowtask.domain.dto.request.CreateUserRequestDto;
import com.falesdev.flowtask.domain.dto.request.UpdateUserRequestDto;
import com.falesdev.flowtask.domain.entity.Role;
import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.mapper.UserMapper;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import com.falesdev.flowtask.service.RoleService;
import com.falesdev.flowtask.service.UserService;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final RoleService roleService;

    @Override
    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(userMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
        return userMapper.toDto(user);
    }

    @Override
    @Transactional
    public UserDto createUser(CreateUserRequestDto userRequestDto) {
        if (userRepository.existsByEmailIgnoreCase(userRequestDto.getEmail())){
            throw new IllegalArgumentException("User already exists with email: " + userRequestDto.getEmail());
        }

        User newUser = userMapper.toCreateUser(userRequestDto);
        newUser.setPassword(passwordEncoder.encode(userRequestDto.getPassword()));
        newUser.setRole(roleService.getRoleById(userRequestDto.getRoleId()));

        User savedUser = userRepository.save(newUser);
        return userMapper.toDto(savedUser);
    }

    @Override
    @Transactional
    public UserDto updateUser(UUID id, UpdateUserRequestDto updateUserRequestDto) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(()-> new EntityNotFoundException("User not found with id: " + id));
        userMapper.updateFromDto(updateUserRequestDto, existingUser);

        if(updateUserRequestDto.getRoleId() != null){
            Role validRole = roleService.getRoleById(updateUserRequestDto.getRoleId());
            existingUser.setRole(validRole);
        }

        if (updateUserRequestDto.getPassword() != null) {
            existingUser.setPassword(passwordEncoder.encode(updateUserRequestDto.getPassword()));
        }

        User updatedUser = userRepository.save(existingUser);
        return userMapper.toDto(updatedUser);
    }

    @Override
    @Transactional
    public void deleteUser(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(()-> new EntityNotFoundException("User not found with id: " + id));
        userRepository.delete(user);
    }
}
