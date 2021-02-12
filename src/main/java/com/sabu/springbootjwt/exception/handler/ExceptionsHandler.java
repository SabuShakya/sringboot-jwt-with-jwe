package com.sabu.springbootjwt.exception.handler;

import com.sabu.springbootjwt.dto.GenericResponse;
import com.sabu.springbootjwt.exception.UnauthorizedException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class ExceptionsHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = {UnauthorizedException.class})
    public ResponseEntity<Object> handleUnauthorizedLoginException(UnauthorizedException exception) {
        GenericResponse genericResponse = new GenericResponse(false, "401", exception.getMessage());
        return new ResponseEntity<>(genericResponse, HttpStatus.UNAUTHORIZED);
    }
}
