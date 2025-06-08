package com.falesdev.flowtask.mapper;

import com.falesdev.flowtask.domain.dto.RoleDto;
import com.falesdev.flowtask.domain.entity.Role;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface RoleMapper {

    RoleDto toDto(Role role);
}
