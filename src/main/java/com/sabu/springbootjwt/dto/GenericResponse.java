package com.sabu.springbootjwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class GenericResponse {

    private boolean success;

    private String code;

    private String message;
}
