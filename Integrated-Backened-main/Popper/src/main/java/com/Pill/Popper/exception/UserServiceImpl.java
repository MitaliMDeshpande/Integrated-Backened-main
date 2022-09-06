package com.Pill.Popper.exception;


import com.Pill.Popper.dao.entity.User;
import com.Pill.Popper.dao.repository.UserRRepository;
import com.Pill.Popper.dao.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRRepository userRepository;
    private ResponseEntity<User> user;

    public UserServiceImpl(UserRRepository userRepository){
        super();
        this.userRepository = userRepository;
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserById(long userId) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if(user.isPresent()){
            return user.get();
        }
        else{
            throw new ResourceNotFoundException("User", "id", userId);
        }
    }

    @Override
    public User updateUser(User user, long userId) throws ResourceNotFoundException {
        Optional<User>usr = userRepository.findById(userId);
        if(usr.isPresent()){
            User user1=usr.get();
            user1.setFirstname(user.getFirstname());
            user1.setLastname(user.getLastname());
            user1.setGender(user.getGender());
            user1.setDob(user.getDob());
            user1.setAge(user.getAge());
            user1.setEmail(user.getEmail());
            user1.setPassword(user.getPassword());
            user1.setMobile_no(user.getMobile_no());
            user1.setAddress(user.getAddress());
            userRepository.save(user1);
            return user1;
        }
        else{

            throw new ResourceNotFoundException("User", "id", userId);
        }
    }

    @Override
    public void deleteUserById(long userId) throws ResourceNotFoundException {
        Optional<User> user= userRepository.findById(userId);
        if(user.isPresent()){
            userRepository.deleteById(userId);
        }
        else{
            throw new ResourceNotFoundException("User", "id", userId);
        }

    }
}