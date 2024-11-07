package com.espinozameridaal.securityexnotes.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


//This JWTService class performs key functions related to JWTs:
//
//Generating a JWT for a user with a given username.
//Extracting specific claims from the token, like username and expiration.
//Validating tokens by comparing them with user details and checking expiration.
//This class offers a straightforward JWT handling service, well-suited for
// adding authentication to a Spring Boot application. Let me know if you'd like
// to discuss any specific part in more detail!


@Service
public class JWTService {

//    secretkey: A base64-encoded secret key,
//    generated using HmacSHA256, to sign and verify JWT tokens.
    private String secretkey;


//    This constructor generates a secret key for HMAC SHA-256 and encodes it in Base64.
//    If the algorithm isn’t available, it throws a runtime exception.
//    The key is then stored in the secretkey field.
    public JWTService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = keyGen.generateKey();
            secretkey = Base64.getEncoder().encodeToString(sk.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

//    Parameters: username – the identifier for the user.
//    Process:
//    Creates an empty claims map, which can store additional data for the token if needed.
//    Sets the subject (username), issuedAt (current time), and expiration (token’s expiration time: 30 hours).
//    Signs the token using the HS256 algorithm with a secret key obtained by getKey().
//    Returns: The generated JWT token as a string.
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims) // Updated from .claims()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 30 * 1000L)) // Fix expiration calculation
                .signWith(getKey(), SignatureAlgorithm.HS256) // Updated for new signature method
                .compact();
    }

//    Purpose: Decodes the base64 secretkey and creates an HMAC SHA-256 SecretKey.
//    Usage: This method provides a secure key for signing and verifying JWTs.
    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);  // Generates a SecretKey using the HS256 algorithm
    }

//    Parameters: token – the JWT token to parse.
//    Returns: The username embedded in the subject claim of the token.
//    Process: Uses the helper method extractClaim with Claims::getSubject
//    to extract the subject field, which corresponds to the username.
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

//    Parameters: token – the JWT token.
//    claimResolver – a function that extracts a specific claim from Claims.
//    Purpose: A generic method to extract a specific claim (like subject or expiration) from a token.
//    Returns: The result of claimResolver, which could be any claim within the token.
    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

//  Purpose: Parses the token to retrieve all claims within it.
//  Returns: A Claims object containing all the data embedded in the JWT.
//  Security: Verifies the token signature with the key obtained from getKey().
    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getKey()).build().parseClaimsJws(token).getBody();
    }
//  Parameters:token – the JWT token to validate.
//  userDetails – user information to cross-check the token’s validity.
//  Process:
//  Extracts the username from the token and verifies it matches userDetails.getUsername().
//  Checks if the token has expired using isTokenExpired.
//  Returns: true if the username matches and the token hasn’t expired; false otherwise.

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
//  Parameters: token – the JWT token.
//  Returns: true if the token has expired; false otherwise.
//  Process: Compares the token’s expiration date to the current time.
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
//  Parameters: token – the JWT token.
//  Returns: The expiration date of the token.
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
