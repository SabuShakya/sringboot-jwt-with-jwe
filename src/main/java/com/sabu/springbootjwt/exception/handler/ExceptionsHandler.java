package com.sabu.springbootjwt.exception.handler;

import com.sabu.openforium.dto.GenericResponse;
import com.sabu.springbootjwt.exception.UnauthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionsHandler {

    @ExceptionHandler(value = UnauthorizedException.class)
    public ResponseEntity<?> handleUnauthorizedLoginException(UnauthorizedException exception) {
        return new ResponseEntity<>(
                new GenericResponse(false, "401", exception.getMessage()),
                HttpStatus.UNAUTHORIZED);
    }
}
