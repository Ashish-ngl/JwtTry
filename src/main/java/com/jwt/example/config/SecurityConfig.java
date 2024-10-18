package com.jwt.example.config;

import com.jwt.example.security.JwtAuthenticationEntryPoint;
import com.jwt.example.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {


    @Autowired
    private JwtAuthenticationEntryPoint point;
    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //defines the security filter chain, which is the sequence of security filters applied to incoming requests.

        http.csrf(csrf -> csrf.disable())
    //CSRF protection is typically used for stateful applications with sessions.
                .authorizeRequests().
                requestMatchers("/home/**").authenticated().
                requestMatchers("/auth/login").permitAll()
                .anyRequest()
        //Any other request (i.e., any request that isn't explicitly defined) also requires the user to be authenticated.
                .authenticated()
                .and().exceptionHandling(ex -> ex.authenticationEntryPoint(point))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // Since JWT is stateless the application must be stateless as well. This disables server-side session
        // creation and ensures that Spring Security doesn't store authentication in a session.
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        //add the custom JwtAuthenticationFilter before the built-in UsernamePasswordAuthenticationFilter
        return http.build();
        //finalizes the configuration and builds the SecurityFilterChain with the defined settings
    }


}
