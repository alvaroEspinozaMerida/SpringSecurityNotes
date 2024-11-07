package com.espinozameridaal.securityexnotes.config;

import com.espinozameridaal.securityexnotes.service.JWTService;
import com.espinozameridaal.securityexnotes.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//@Component: Marks this class as a Spring-managed bean,
// so it can be automatically detected and injected where needed.
@Component

public class JwtFilter extends OncePerRequestFilter {

//    @Autowired JWTService: The JWTService is a custom service that likely handles JWT-related functionality,
//    such as extracting the username from the token and validating the token.
    @Autowired
    private JWTService jwtService;

//    @Autowired ApplicationContext: The ApplicationContext is used to retrieve beans from the Spring container dynamically.
//    In this case, it’s used to fetch the MyUserDetailsService to load user details for authentication.

    @Autowired
    ApplicationContext context;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)throws ServletException, IOException {

//        authHeader: The JWT token is typically passed in the HTTP Authorization header as a Bearer token.
//        The header looks like this: Authorization: Bearer <jwt_token>.
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
//Checking for the Bearer token: The code checks if the Authorization header is present and starts with Bearer .
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            //Extracting the token: If the header starts with Bearer ,
            // the actual token is extracted by removing the first 7 characters.
            token = authHeader.substring(7);
            //Extracting the username: The token is passed to the jwtService to extract
            //the username (likely contained in the JWT's payload).
            username = jwtService.extractUserName(token);
        }

//SecurityContextHolder.getContext().getAuthentication() == null: This checks if the current request is already authenticated.
// If it's not, the filter proceeds with authenticating the request.

//username != null: This ensures that a valid username was extracted from the token.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            Loading user details: The MyUserDetailsService is used to load the user’s details
//            from the database (based on the username extracted from the JWT).
//            This retrieves the UserDetails object for the authenticated user.
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);
//            Validating the token: The jwtService.validateToken(token, userDetails) checks whether the JWT
//            is valid for the given UserDetails. This could involve checking the token’s signature, expiration,
//            and any claims it contains.
            if (jwtService.validateToken(token, userDetails)) {
//            Creating an Authentication object: If the token is valid, a UsernamePasswordAuthenticationToken object is
//            created, which represents a fully authenticated user. It takes the user’s details and authorities (roles).
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource()
                        .buildDetails(request));

//             Setting the Security Context: The authentication object is stored in the SecurityContextHolder,
//             which Spring Security uses to manage the user’s authentication for the current request.

//              From this point forward, the user is considered authenticated, and their identity will be available throughout
//              the rest of the request processing (including access control checks).
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

//        After the JWT has been validated and the user authenticated (if the token is valid), the filter chain continues,
//        and the request proceeds to the next filter or controller.
        chain.doFilter(request, response);



    }
}
