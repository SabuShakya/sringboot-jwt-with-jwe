package com.sabu.springbootjwt.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserRequestDTO {

    private String name;

    private String username;

    private String password;
}
