## JWT ##

JSON Web Tokens is a standard used for securing REST apis. It is a standard that defines a compact and self-contained 
way for securely transmitting information between parties as a JSON object. JWTs can be signed using a secret 
(with the HMAC algorithm) or a public/private key pair using RSA or ECDSA

### JSON Web Token Structure ###

JSON Web Tokens consists of three parts separated by dots(.), which are 

- header
- payload
- signature

#### Header ####

It consists of two parts: type of token, which is JWT and the signing algorithm being used, like HMAC, SHA256 or RSA.

eg:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
This header is the Base64Url encoded to form the first part of JWT.

#### Payload ####

It is the second part which contains the claims. Claims are statements about an entity(user) 
and additional data. There are three types of claims:

- *Registered Claims* : Set of predefined claims. Examples: iss(issuer),exp(expiration time), sub(subject),sud(audience) etc.

- *Public claims* : Public claims are like public API that defined for public consumption. They should be well documented. 
They should be defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace.

- *Private claims* : Custom claims created to share information between parties that agree on using 
them and are neither registered nor public claims.

```json
{
  "sub": "1234567890",
  "name": "Sabu",
  "admin": true
}
```
The payload is then Base64Url encoded to form the second part of the JSON Web Token.

#### Signature ####
It is used to verify the message wasn't changed and in case of tokens signed with a private key, it can verify that the 
sender of JWT is who it says it is.
We have to take the encoded header, encoded payload, a secret, the algorithm specified in the header and sign that.
For example, if we are using HMAC SHA256 algorithm:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

The output is three Base64-URL strings separated by dots. 
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
### PROCEDURE ###

![Alt text](./jwt.jpg?raw=true "Title")

### Implementation ###

Let us create a spring boot application with spring-security, spring-data-jpa and mysql connector dependencies.
For jwt add the following dependency:
```xml
<dependencies>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>
    <dependency>
        <groupId>javax.xml.bind</groupId>
        <artifactId>jaxb-api</artifactId>
    </dependency>
</dependencies>
```
or, goto https://jwt.io/#libraries-io to get the required dependencies.

We will be creating 3 api's, one to Signup a user,one to login and a simple hello api to verify authentication.
The work flow is depicted in the diagram:

![Alt Text](./workflow.png?raw=true "Title")
Diagram: 1 

Create a Users entity.
```java
package com.sabu.springbootjwt.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "users")
@Getter
@Setter
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "name")
    private String name;
}
```
Repository class for above entity.
```java
package com.sabu.springbootjwt.repository;

import com.sabu.springbootjwt.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users,Long> {
    Users findByUsername(String username);
}
```
UserService Interface and UserServiceImpl to create and get user by username:

```java
package com.sabu.springbootjwt.service;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.entity.Users;

public interface UserService {

    public void createUser(UserRequestDTO user);

    public Users findUserByUsername(String name);

}
```
```java
package com.sabu.springbootjwt.service.impl;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.entity.Users;
import com.sabu.springbootjwt.repository.UserRepository;
import com.sabu.springbootjwt.service.UserService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void createUser(UserRequestDTO user) {

        Users users = new Users();
        users.setName(user.getName());
        users.setUsername(user.getUsername());
        users.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userRepository.save(users);
    }

    @Override
    public Users findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
```
Next we create a UserController and add api that creates a user(or signup).
```java
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
        return new ResponseEntity<>("User created successfully.", HttpStatus.OK);
    }
}
```
Next for login,
```java
package com.sabu.springbootjwt.controller;

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
            return ResponseEntity.ok(new LoginResponse(jwtToken));
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
}
```
When the user login's with username and password, we will authenticate the username and password, and if they are valid
we will generate a jwt token and return it in the response.
Spring Security behind the hood will perform the following:
1. The username and password are obtained and combined into an instance of UsernamePasswordAuthenticationToken (an instance
of the Authentication interface).
2. The token is passed to an instance of AuthenticationManager for validation.
3. The AuthenticationManager returns a fully populated Authentication instance on successful authentication.

```java
package com.sabu.springbootjwt.service;

import com.sabu.springbootjwt.dto.UserRequestDTO;
import com.sabu.springbootjwt.util.JwtUtil;
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
    private final JwtUtil jwtUtil;
    private final UserAuthenticationService userAuthenticationService;

    @Autowired
    public AuthenticationService(AuthenticationManager authenticationManager,
                                 JwtUtil jwtUtil, UserAuthenticationService userAuthenticationService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
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
        String token = "Bearer " + jwtUtil.generateToken(userDetails); 
        return token;
    }
}
```
In loginUser method, as explained above we pass in the username and password to UsernamePasswordAuthenticationToken 
instance to authenticate. Once successfully authenticated, using UserDetails object we will generate a jwt token ,
append it with a token prefix("Bearer ") and return the token as response.

Next let's create a SecurityConfig to create the authentication manager bean and then UserAuthenticationService followed by
JwtUtil.

```java
package com.sabu.springbootjwt.config;

import com.sabu.springbootjwt.filter.JwtRequestFilter;
import com.sabu.springbootjwt.service.UserAuthenticationService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserAuthenticationService authenticationService;

    public SecurityConfig(UserAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(authenticationService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                // telling not to authorize requests for these apis
                .antMatchers("/api/v1/createUser").permitAll()
                .antMatchers("/login").permitAll()
                .anyRequest()
                .authenticated();
    }

    /*
     * This bean is required while calling authenticationManager in our login to authenticate user*/
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

Task of Authentication Manager is to Authenticate the user. So it sends the user name to Authentication provider.
Authentication Provider calls loadUserByUsername() method and passes user name of type String which returns userDetails Object.

```java
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

```

This userDetails object contains all necessary information for authentication, such as username, password, isEnabled etc.

```java
package com.sabu.springbootjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private String SECRET_KEY = "secret";

    public String extractUsername(String token) {
        // equivalent to:
      /* 
        Claims claims = extractAllClaims(token);
        String username = claims.getSubject();
        return username;
        */
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // parsing happens here and returns claims
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

Now let's run our application, create a user and test our login.
First let's create a user, i.e sign up

![Alt Text](./signup.jpg?raw=true "Sign up")

Then login using the above created user.

![Alt Text](./login.jpg?raw=true "Login")

We get a token in response which we will be using to access other resources. We have successfully implemented step 1 of 
diagram: 1. Next we will implement step 2, that is verifying the token when we get any other requests.

Let's add a simple api that returns a text.

```java
package com.sabu.springbootjwt.controller;

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
}
```

Next, we have to add a filter, that intercepts every request only once and verifies the token sent in the header.

```java
package com.sabu.springbootjwt.filter;

import com.sabu.springbootjwt.service.UserAuthenticationService;
import com.sabu.springbootjwt.util.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 * this filter is going to intercept each request only once
 * */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserAuthenticationService userAuthenticationService;

    public JwtRequestFilter(JwtUtil jwtUtil, UserAuthenticationService userAuthenticationService) {
        this.jwtUtil = jwtUtil;
        this.userAuthenticationService = userAuthenticationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = httpServletRequest.getHeader("Authorization");

        String jwtToken = null;
        String username = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwtToken = authorizationHeader.replace("Bearer ", "");
            username = jwtUtil.extractUsername(jwtToken);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userAuthenticationService.loadUserByUsername(username);
                if (jwtUtil.validateToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    usernamePasswordAuthenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
```

The filter intercepts the incoming request and checks the header. If the authorization header is available, we extract the 
username from token and if the security context doesn't have the  authenticated, we will validate the token by passing token and
a constructed UserDetails object to the util method of JwtUtil(i.e. parse the token). If the jwt is valid, we will set 
the userdetails and other details to UsernamePasswordAuthenticationToken and set it to the security context.

At last, we will have to tell the SecurityConfig to interject our filter to the filter chain.

```java
package com.sabu.springbootjwt.config;

import com.sabu.springbootjwt.filter.JwtRequestFilter;
import com.sabu.springbootjwt.service.UserAuthenticationService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserAuthenticationService authenticationService;
    private final JwtRequestFilter jwtRequestFilter;

    public SecurityConfig(UserAuthenticationService authenticationService, JwtRequestFilter jwtRequestFilter) {
        this.authenticationService = authenticationService;
        this.jwtRequestFilter = jwtRequestFilter;
    }
    /*other codes removed for brevity*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/createUser").permitAll()
                .antMatchers("/login").permitAll()
                .anyRequest()
                .authenticated()
                // telling spring security not to create(handle) sessions since we will be  using JWT
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // add our filter to the filter chain
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
    /*other codes */  
}
```
Now let's run our code and test the apis. Once again login using the credentials created before. Then try accessing our 
hello api by using the token generated in login api. We add the token to *Authorization* header while sending the request.

![Alt text](./helloapi.jpg?raw=true "Hello Api")

If we try to access the hello api without sending the token, we will get 403 Forbidden error.

![Alt text](./forbidden.jpg?raw=true "Hello Api")

References:
- [Spring Boot + Spring Security + JWT from scratch](https://www.youtube.com/watch?v=X80nJ5T7YpE&ab_channel=JavaBrains)
- [How to Set Up Java Spring Boot JWT Authorization and Authentication](https://www.freecodecamp.org/news/how-to-setup-jwt-authorization-and-authentication-in-spring/)
- [Spring Security](https://amigoscode.com/)
- https://docs.spring.io/spring-security/site/docs/3.1.x/reference/technical-overview.html#tech-userdetailsservice
