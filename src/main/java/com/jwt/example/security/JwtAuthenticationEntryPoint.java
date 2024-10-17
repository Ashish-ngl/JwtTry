package com.jwt.example.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

//Method of this class is called whenever as exception is thrown due to
// unauthenticated user trying to access the resource that required authentication.
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
//    AuthenticationEntryPoint, an interface from Spring Security.
//    It is used to handle authentication errors,
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException{
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println("Access Denied !! " + authException.getMessage());
    }
}
