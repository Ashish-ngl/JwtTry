package com.jwt.example.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
//provides essential methods for generating, validating, and parsing JWT tokens.
public class JwtHelper {

    //requirement :
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

//   secret key used for signing the JWT
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    //retrieves the username (subject) embedded in the token.
    //uses a helper method getClaimFromToken to extract the claim.
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

//    retrieves a specific claim from the token using a claimsResolver function,
//    which could be extracting the subject, expiration, or other claims.
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // parses the entire JWT and retrieves all the claims. It uses the secret key to
    // ensure the JWT is valid and hasn't been tampered with. It returns the claims (payload) of the token.
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder() // Use parserBuilder instead of parser
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes())) // Set the signing key using the updated method
                .build() // Build the parser
                .parseClaimsJws(token) // Parse the token
                .getBody(); // Retrieve the claims from the token
    }


    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //This method generates a new JWT token for a given UserDetails object.
    // It calls the doGenerateToken() method, passing an
    // empty map for additional claims and the username as the subject.
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims) // Sets any additional claims (in this case, none).
                .setSubject(subject) //Sets the subject, which is usually the username.
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS512)
                //Signs the token using the HS512 algorithm and the secret key.
                .compact(); //Serializes the JWT into a URL-safe string.
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        //checks username extracted from the token matches
        // the one in UserDetails(AppConfig file wala).
        // This username(AppConfig) is embedded in the JWT as the subject,
        // and it is later extracted and compared to the UserDetails when validating the token.
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


}