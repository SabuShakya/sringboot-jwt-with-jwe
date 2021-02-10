package com.sabu.springbootjwt.controller;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping("/createUser")
    private ResponseEntity<?> createUser(@RequestBody UserRequestDTO user) {
        userService.createUser(user);
//        GenericResponse genericResponse = new GenericResponse(true, ResponseCodeConstants.SUCCESS,"User created successfully");
        return new ResponseEntity<>("User created successfully.", HttpStatus.OK);
    }
}
