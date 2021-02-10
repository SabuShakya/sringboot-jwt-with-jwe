package com.sabu.springbootjwt.service;

import com.sabu.springbootjwt.entity.Users;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserAuthenticationService implements UserDetailsService {

    private final UserService userService;

    public UserAuthenticationService(UserService userService) {
        this.userService = userService;
    }

    /*
    * The core idea is to return the User instance with populated values
    * which will be used by the authentication manager to authenticate.
    * so it acts a provider
    * */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userService.findUserByUsername(username);
        if (user == null)
            throw new UsernameNotFoundException("User " + username + " not found!");

        UserDetails userDetails = new User(
                user.getUsername(),
                user.getPassword(),
                new ArrayList<>()
        );
        return userDetails;
    }
}
