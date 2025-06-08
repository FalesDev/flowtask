package com.falesdev.flowtask.service;

import com.falesdev.flowtask.domain.entity.Role;

import java.util.UUID;

public interface RoleService {
    Role getRoleById(UUID id);
}
