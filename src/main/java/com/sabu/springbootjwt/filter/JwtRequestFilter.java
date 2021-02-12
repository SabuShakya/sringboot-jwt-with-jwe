package com.sabu.springbootjwt.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sabu.springbootjwt.exception.UnauthorizedException;
import com.sabu.springbootjwt.service.UserAuthenticationService;
import com.sabu.springbootjwt.util.TokenUtil;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

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

    private final TokenUtil tokenUtil;
    private final UserAuthenticationService userAuthenticationService;

    @Autowired
    private HandlerExceptionResolver handlerExceptionResolver;

    public JwtRequestFilter(TokenUtil tokenUtil, UserAuthenticationService userAuthenticationService) {
        this.tokenUtil = tokenUtil;
        this.userAuthenticationService = userAuthenticationService;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = httpServletRequest.getHeader("Authorization");

        String jwtToken = null;
        String username = null;
        JWTClaimsSet jwtClaimsSet = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwtToken = authorizationHeader.replace("Bearer ", "");
            try {
                jwtClaimsSet = tokenUtil.parseEncryptedToken(jwtToken);
            } catch (Exception e) {
                handlerExceptionResolver.resolveException(httpServletRequest, httpServletResponse, null,
                        new UnauthorizedException("Token not valid."));
                return;
            }
            username = jwtClaimsSet.getSubject();

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userAuthenticationService.loadUserByUsername(username);
                if (tokenUtil.validateToken(jwtClaimsSet, userDetails)) {
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
