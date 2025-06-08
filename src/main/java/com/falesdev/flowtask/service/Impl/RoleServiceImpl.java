package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.domain.entity.Role;
import com.falesdev.flowtask.repository.postgres.RoleRepository;
import com.falesdev.flowtask.service.RoleService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Role getRoleById(UUID id) {
        return roleRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Role not found"));
    }
}
