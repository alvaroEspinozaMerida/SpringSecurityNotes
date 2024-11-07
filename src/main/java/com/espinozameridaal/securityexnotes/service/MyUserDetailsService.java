package com.espinozameridaal.securityexnotes.service;


import com.espinozameridaal.securityexnotes.model.UserPrincipal;
import com.espinozameridaal.securityexnotes.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.espinozameridaal.securityexnotes.repo.UserRepo;


//
//The MyUserDetailsService class plays a critical role in Spring Security
// by providing the user details (like username, password, and roles)
// necessary for authentication. Here's a breakdown of its purpose
// and how it contributes to the security flow of your Spring Boot application:


//@Service: This annotation marks the class as a service component in the Spring context.
// It's a specialized form of @Component, indicating that it's a business service class
// that can be injected elsewhere in the application.

//Implements UserDetailsService: This interface is part of Spring Security,
// and it's used to fetch user-specific data during the authentication process.
// Spring Security calls loadUserByUsername(String username) to retrieve the user
// trying to log in.
@Service
public class MyUserDetailsService implements UserDetailsService {

//    @Autowired UserRepo:
//The UserRepo is injected into this service, which allows you to fetch
// user data from the database (likely using JPA).

//UserRepo provides methods to access your database's Users table (or entity)
// and is expected to have a method like findByUsername(String username)
// to look up a user by their username.

    @Autowired
    private UserRepo userRepo;


//This method is the core functionality of the UserDetailsService interface.
// It is called during the authentication process to load user details
// (like username, password, and roles) from the database.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

//        Fetch User from Database (userRepo.findByUsername(username)):
//
//The repository method findByUsername(username) is called to look
// up the user by their username in the database.
//The Users object returned represents the user from your database,
// which likely includes fields such as username, password, roles, etc.
        Users user = userRepo.findByUsername(username);

//If userRepo.findByUsername() returns null, the method throws a UsernameNotFoundException, indicating that the user was not found. This will result in an authentication failure with Spring Security.
//This ensures that only users who exist in the database can be authenticated.
        if (user == null) {
            System.out.println("User Not Found");
            throw new UsernameNotFoundException("user not found");
        }
//
//If the user is found, the method returns a UserPrincipal object, which is an implementation of UserDetails.
//UserPrincipal wraps the Users object and provides necessary security details like the username, password, and authorities (roles) to Spring Security.
//Spring Security will then use this UserDetails object to authenticate the user and manage their session (if sessions are enabled).

        return new UserPrincipal(user);
    }
}

//Security Implications:
//Secure Password Handling: The UserPrincipal class should return the user’s password in an encrypted form.
// Ensure that the password stored in the database is hashed (e.g., using BCrypt) and not stored as plain text.
//Role Management: The UserPrincipal class should return the authorities (roles) of the user, which are used for authorization purposes. For example, roles like ROLE_ADMIN or ROLE_USER can be checked in your security configuration to restrict access to certain endpoints.



//Summary of Security Flow:
//User Attempts Login: A user submits their credentials (username and password)
// to the Spring Boot application (e.g., via /login endpoint or through Basic Auth headers).

//Spring Security Calls loadUserByUsername: Spring Security invokes
// the MyUserDetailsService.loadUserByUsername(String username) method.

//User Lookup: The method fetches the user details from the database using UserRepo.findByUsername(username).

//Return UserPrincipal: If the user exists, a UserPrincipal object is returned,
// containing the user's details (username, password, roles).

//Authentication: Spring Security checks the returned user’s credentials (password) and authorities
// (roles) to determine whether the login attempt is valid and what resources the user is allowed to access.