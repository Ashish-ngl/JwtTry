package com.jwt.example.models;


import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class JwtRequest {
    private String email;
    private String password;
}
//When a user tries to log in by making a POST request to the login endpoint (/auth/login),
// the server expects the request body to contain the email and password.
// This data is then mapped into a JwtRequest object, which will be used in the authentication process.

//{
//    "email": "user@example.com",
//    "password": "password123"
//}
//JwtRequest jwtRequest = new JwtRequest("user@example.com", "password123");