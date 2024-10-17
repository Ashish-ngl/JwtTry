package com.jwt.example.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//The JwtAuthenticationFilter is a custom filter that intercepts each incoming HTTP request
// and checks for a valid JWT token in the Authorization header.
// If the token is valid, it sets up the security context for the authenticated user(i.e sets
// the necessary authentication details for Spring Security to manage the user's session)
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
    //Logs messages for debugging purposes.

    @Autowired
    private JwtHelper jwtHelper;
//injected to help with JWT operations like extracting usernames and validating tokens.

    @Autowired
    private UserDetailsService userDetailsService;
    //to fetch user details based on the username extracted from the token


//     main method where the JWT filtering logic happens.
//     It intercepts every HTTP request, processes the JWT,
//     and forwards the request down the filter chain.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Authorization

        String requestHeader = request.getHeader("Authorization");
        //Bearer 2352345235sdfrsfgsdfsdf
        logger.info(" Header :  {}", requestHeader);
        String username = null;
        String token = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
        //it extracts the JWT token by removing the "Bearer " prefix (first 7 characters).
            token = requestHeader.substring(7);
            try {

                username = this.jwtHelper.getUsernameFromToken(token);

            } catch (IllegalArgumentException e) {
                logger.info("Illegal Argument while fetching the username !!");
                e.printStackTrace();
            } catch (ExpiredJwtException e) {
                logger.info("Given jwt token is expired !!");
                e.printStackTrace();
            } catch (MalformedJwtException e) {
                logger.info("Some changed has done in token !! Invalid Token");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();

            }


        } else {
            logger.info("Invalid Header Value !! ");
        }

        //checks SecurityContextHolder (which holds authentication details for the current session)
        // doesn't already have an authentication object (i.e., the user is not yet authenticated).
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {


        //Loads user details from the username extracted from the token.
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            if (validateToken) {

                //set the authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);


            } else {
                logger.info("Validation fails !!");
            }


        }
//The filter passes the request and response down the filter chain, allowing
//the next filters to execute. This is necessary to continue the request lifecycle.
        filterChain.doFilter(request, response);


    }
}
