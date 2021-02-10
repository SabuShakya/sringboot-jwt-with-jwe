package com.sabu.springbootjwt.controller;

import com.sabu.springbootjwt.dto.LoginResponse;
import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.service.AuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    private ResponseEntity<?> loginUser(@RequestBody UserRequestDTO userRequestDTO) {
        try {
            String jwtToken = authenticationService.loginUser(userRequestDTO);
            // add the token to response header
//            HttpHeaders httpHeaders = new HttpHeaders();
//            httpHeaders.add("Authorization", jwtToken);
//            return new ResponseEntity<>(httpHeaders, HttpStatus.OK);
            // or
            return ResponseEntity.ok(new LoginResponse(jwtToken));
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

    }
}
