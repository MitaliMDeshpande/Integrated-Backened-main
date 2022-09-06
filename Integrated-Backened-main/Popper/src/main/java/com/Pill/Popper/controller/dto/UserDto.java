package com.Pill.Popper.controller.dto;

import com.Pill.Popper.dao.entity.RoleEntity;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter

public class UserDto {
    private String username;
    private String email;
    private String password;
    private Set<RoleEntity> roles;


}
