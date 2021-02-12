package com.sabu.springbootjwt.controller;

import com.sabu.springbootjwt.exception.UnauthorizedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class TestController {

    @GetMapping("/hello")
    public String hello(){
        return  "Hello Spring Boot JWT";
    }

    @GetMapping("/test")
    public String test(){
        throw new UnauthorizedException("TESTING FROM CONTROLLER");
//        return  "Hello Spring Boot JWT";
    }
}
