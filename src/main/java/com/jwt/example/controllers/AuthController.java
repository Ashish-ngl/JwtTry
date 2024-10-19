package com.jwt.example.controllers;


import com.jwt.example.entities.RefreshToken;
import com.jwt.example.entities.User;
import com.jwt.example.models.JwtRequest;
import com.jwt.example.models.JwtResponse;
import com.jwt.example.models.RefreshTokenRequest;
import com.jwt.example.repositories.UserRepository;
import com.jwt.example.security.JwtHelper;
import com.jwt.example.services.RefreshTokenService;
import com.jwt.example.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

// it handles user login, authenticates the provided credentials,
// and generates a JWT token if authentication is successful.
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private AuthenticationManager manager;
//responsible for performing the actual authentication process based on the user’s credentials (email and password).

    @Autowired
    private JwtHelper helper;

    private Logger logger = LoggerFactory.getLogger(AuthController.class);


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {

    //passing in the user's email and password to authenticate the credentials using AuthenticationManager
        this.doAuthenticate(request.getEmail(), request.getPassword());

//If authentication is successful, it retrieves the UserDetails of the authenticated user
//Once authenticated, the UserDetailsService fetches the user from the database via the
// loadUserByUsername() method in CustomUserDetailService.
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());

        //generate token with retrieved userdetails
        String token = this.helper.generateToken(userDetails);
        RefreshToken refreshToken=refreshTokenService.createRefreshToken(userDetails.getUsername());

        JwtResponse response = JwtResponse.builder()
                .jwtToken(token)
                .refreshToken(refreshToken.getRefreshToken())
                .username(userDetails.getUsername()).build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

  //performs the actual authentication process using the AuthenticationManager.
    private void doAuthenticate(String email, String password) {

    //creates an instance of UsernamePasswordAuthenticationToken using the email (as username) and password provided by the user.
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            manager.authenticate(authentication);
    //AuthenticationManager delegates the actual authentication logic to one or more AuthenticationProvider
            // implementations. In your case, it will typically be an instance of DaoAuthenticationProvider(which is configured in securityConfig file)
            // (if using database-backed user authentication) or an InMemoryUserDetailsManager
            // (if users are stored in memory).
    //AuthenticationProvider compares the provided password (from the login request)
            // with the stored password (from the UserDetails)
//If authentication is successful, the resulting Authentication object is returned to the AuthenticationManager

        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(" Invalid Username or Password  !!");
        }

    }
    @PostMapping("/refresh")
    //passing the RT in the request
    public JwtResponse refreshJwtToken(@RequestBody RefreshTokenRequest request){
        //verify it
        RefreshToken refreshToken= refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        //if valid , retrieve the user associated with it
        User user=refreshToken.getUser();
        //generate new Jwt for the user
        String token= helper.generateToken(user);
        //send the Jwt back along with the same RT, since its expiry may have extended
        return JwtResponse.builder()
                .refreshToken(refreshToken.getRefreshToken())
                .jwtToken(token)
                .username(user.getEmail())
                .build();
    }

    @ExceptionHandler(BadCredentialsException.class)
    public String exceptionHandler() {
        return "Credentials Invalid !!";
    }

    @PostMapping("/create-user")
    public User createUser(@RequestBody User user){
        return userService.createUser(user);
    }

}
