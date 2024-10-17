package com.jwt.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class AppConfig {

    @Bean
//    UserDetailsService: This interface is required to load user-specific data.
//    Spring Security uses it to authenticate users. (loadByUsername method)
    public UserDetailsService userDetailsService() {

//        UserDetails object holds user information (username, password, roles).
//        This is crucial for authentication and authorization.
        UserDetails user1 = User.builder().
                username("ashish")
                .password(passwordEncoder().encode("abc")).roles("ADMIN").
                build();
        UserDetails user2 = User.builder().
                username("harsh")
                .password(passwordEncoder().encode("abc")).roles("ADMIN").
                build();
        return new InMemoryUserDetailsManager(user1,user2);
//         implementation of UserDetailsService that stores user details in memory.
//         In a real-world app, you'd likely use a database

//When a user attempts to authenticate (login), Spring Security will look for the user
// in the UserDetailsService implementation (in this case, the InMemoryUserDetailsManager)
// based on the provided username.During this process, Spring loads the UserDetails object
// corresponding to the username "ashish".
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
