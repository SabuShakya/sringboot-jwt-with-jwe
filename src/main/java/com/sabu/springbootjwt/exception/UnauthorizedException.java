package com.sabu.springbootjwt.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UnauthorizedException  extends RuntimeException {
    public UnauthorizedException(String msg) {
        super(msg);
    }
}
