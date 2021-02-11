package com.sabu.springbootjwt.service;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.util.TokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final TokenUtil tokenUtil;
    private final UserAuthenticationService userAuthenticationService;

    @Autowired
    public AuthenticationService(AuthenticationManager authenticationManager,
                                 TokenUtil tokenUtil, UserAuthenticationService userAuthenticationService) {
        this.authenticationManager = authenticationManager;
        this.tokenUtil = tokenUtil;
        this.userAuthenticationService = userAuthenticationService;
    }


    public String loginUser(UserRequestDTO userRequestDTO) throws Exception {
        try {
            // This authenticates the user and throws exception if not authenticated.
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    userRequestDTO.getUsername(),
                    userRequestDTO.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password.", e);
        }
        UserDetails userDetails = userAuthenticationService.loadUserByUsername(userRequestDTO.getUsername());
        String token = "Bearer " + tokenUtil.generateToken(userDetails);
        return token;
    }

}
