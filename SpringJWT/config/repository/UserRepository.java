package com.jwt.SpringJWT.config.repository;

import com.jwt.SpringJWT.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
