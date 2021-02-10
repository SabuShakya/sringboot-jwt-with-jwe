package com.sabu.springbootjwt.service;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.entity.Users;

public interface UserService {

    public void createUser(UserRequestDTO user);

    public Users findUserByUsername(String name);

}
