package com.sabu.springbootjwt.repository;

import com.sabu.springbootjwt.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users,Long> {

    Users findByUsername(String username);
}
