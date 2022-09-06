package com.Pill.Popper.dao.repository;


import com.Pill.Popper.dao.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRRepository extends JpaRepository<User, Long> {


}
