package com.Pill.Popper.dao.service;

import com.Pill.Popper.dao.entity.User;
import com.Pill.Popper.exception.ResourceNotFoundException2;

import java.util.List;

public interface UserService {

    User save(User user);

    List<User> getAllUsers();

    User getUserById(long userId) throws ResourceNotFoundException2;

    User updateUser(User user, long userId) throws ResourceNotFoundException2;

    void deleteUserById(long userId) throws ResourceNotFoundException2;
}