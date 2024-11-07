package com.espinozameridaal.securityexnotes.service;

import com.espinozameridaal.securityexnotes.model.Users;
import com.espinozameridaal.securityexnotes.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
//    UserRepo userRepo:
//    The UserRepo is the repository interface for interacting
//    with the user data in the database (CRUD operations).
//    This is used to save or retrieve user data.
    @Autowired
    private UserRepo userRepo;
//  JWTService jwtService: The JWTService is a custom service for generating JWT tokens.
//  This service is used here to generate tokens upon successful authentication.
    @Autowired
    private JWTService jwtService;

//    BCryptPasswordEncoder encoder: The password encoder is used to hash and verify user passwords securely.
//    Here, it’s instantiated with a strength of 12 (recommended for good security without excessive computational cost).
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

//    AuthenticationManager authenticationManager:
//    The AuthenticationManager is provided by Spring Security and handles the process of authenticating
//    a user based on the credentials (username and password) provided.
    @Autowired
    private AuthenticationManager authenticationManager;

//    This method handles user registration by taking a Users object, encoding the password, and saving the user to the database.
//
//Password Encoding:
// encoder.encode(user.getPassword()) hashes the password using BCrypt before saving it.
// This ensures that passwords are stored securely.

//Saving the User:
// userRepo.save(user) persists the Users object with the encoded password to the database.
// The method returns the saved Users object, which now has a hashed password.
    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepo.save(user);
    }
//The verify method is responsible for authenticating the user’s credentials and generating
// a JWT token if authentication is successful.
//
//Authentication Process:
//authenticationManager.authenticate(...) is called with a UsernamePasswordAuthenticationToken,
// which holds the user’s username and password.
//The authenticationManager checks these credentials against the stored data
// (using the UserDetailsService and password encoder configured in Spring Security).
//If authentication is successful, it returns an Authentication object that represents the authenticated user.
//
// Token Generation:
//After successful authentication, the method calls jwtService.generateToken(user.getUsername()) to create a JWT token using the user’s username. This token is returned as a string and can be used to authenticate future requests.
//Failure Response: If authentication fails, the method returns "fail".
// This can be used by the controller to handle unsuccessful login attempts.

    public String verify(Users user) {
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(user.getUsername());
        }
        return "fail";
    }


}


//register: Takes in a Users object, encodes the password,
// and saves the user to the database. It returns the saved Users object.
//verify: Takes in a Users object, authenticates it using the AuthenticationManager,
// and if successful, generates and returns a JWT token for the user.
// If authentication fails, it returns "fail".