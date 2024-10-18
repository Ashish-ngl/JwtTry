package com.jwt.example.models;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class JwtResponse {
    private String jwtToken;
    private String username;
    private String refreshToken;
}
//After successful login, the client needs the JWT token to include it in the
// headers for future API requests (for example, as Authorization: Bearer eyJhbGciOiJIUzI1...).
// The JwtResponse class holds and delivers this token to the client.
