package com.espinozameridaal.securityexnotes.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


//Marks the class as a configuration class, where beans are defined.
@Configuration
//Enables Spring Security for the application. This annotation triggers
// Spring's web security support and allows customization of the security configuration
@EnableWebSecurity

public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

//        csrf(customizer -> customizer.disable()):
//
// Disabling CSRF: CSRF (Cross-Site Request Forgery) protection is disabled here.
// Disabling CSRF is often done in stateless APIs (like those secured by JWT)
// where CSRF tokens aren’t needed. However, in applications that involve forms
// or session-based authentication, CSRF protection should generally be enabled.

// OLDER VERSION
//        authorizeHttpRequests(request -> request.anyRequest().authenticated()):
//
//Authorization: This line enforces that all requests to the application must be authenticated.
// You can further customize this to allow certain endpoints (like login or registration)
// to be accessed publicly using .permitAll() for specific routes.


// NEWER VERSION
//      requestMatchers("register", "login").permitAll():
//
//This line specifies that the register and login endpoints are publicly accessible without authentication.
// Users can hit these endpoints without being authenticated, which makes sense because users need to register
// and log in without prior authentication.
//
//This is useful for allowing unauthenticated users to access certain endpoints (like signing up or logging in)
// while keeping other parts of the application secured.
//

//        anyRequest().authenticated():
//
//This ensures that all other requests (except those specifically allowed with permitAll()) require authentication.
//After a user registers or logs in, they need to provide valid credentials or a valid JWT token to access any other endpoints.


//        httpBasic(Customizer.withDefaults()):
//
//HTTP Basic Authentication: This enables basic authentication, where users must provide a
// username and password in every request (sent via HTTP headers).
// This is a simple but less secure method, usually for stateless APIs or testing environments.

//  sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)):
//
//Stateless Session: This line sets the session management policy to stateless, meaning that the
// server won’t store any session data. This is essential for REST APIs using JWT tokens, where
// each request must include the authentication token, and no session is maintained on the server.

//.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
//
//Adding a JWT Filter: This line adds a custom JWT filter (jwtFilter) to the security filter chain.
// It ensures that the filter runs before the UsernamePasswordAuthenticationFilter.
//
//Purpose of JWT Filter: The jwtFilter intercepts HTTP requests, extracts the JWT token from the request
// (usually from the Authorization header), and validates it.
//
//If the token is valid, the filter sets up the security context for the authenticated user.
//
//If the token is invalid or absent, the request will be rejected,
// or the user will be treated as unauthenticated.

//Why addFilterBefore?: The JWT filter is added before the UsernamePasswordAuthenticationFilter,
// which is the default filter that handles form-based login and basic authentication.
// By placing the JWT filter before this, you ensure that JWT-based authentication is processed first.

        return http.csrf(customizer -> customizer.disable()).
                authorizeHttpRequests(request -> request
                        .requestMatchers("register","login")
                        .permitAll()
                        .anyRequest()
                        .authenticated()).
                httpBasic(Customizer.withDefaults()).
                sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }


//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        UserDetails user1 = User
//                .withDefaultPasswordEncoder()
//                .username("kiran")
//                .password("k@123")
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User
//                .withDefaultPasswordEncoder()
//                .username("harsh")
//                .password("h@123")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user1, user2);
//    }

//    This method configures the authentication provider for the application.
//    It uses DaoAuthenticationProvider, which is a standard provider used when
//    retrieving user details from a database or another persistent storage.
    @Bean
    public AuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider: This is the default authentication provider
//        for Spring Security that uses the UserDetailsService to load user details.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        Password Encoder:
//
//NoOpPasswordEncoder: This encoder does not encrypt passwords
// (i.e., it stores them in plain text). This is highly insecure
// and should never be used in production.
//Instead, you should replace this with a more secure encoder like BCryptPasswordEncoder.
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));

//This links the custom UserDetailsService (likely your MyUserDetailsService)
// to the authentication provider, so it can load users from your database.
        provider.setUserDetailsService(userDetailsService);


        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }



}




//Summary of Key Points
//Security Filter Chain: Configures basic authentication, disables CSRF, and sets the session policy to stateless.
//In-Memory Authentication: (Currently commented out) It provides two users (kiran and harsh) with basic roles for testing purposes.
//Authentication Provider: Configures a DaoAuthenticationProvider that uses a plain-text password encoder (insecure) and retrieves user details from the UserDetailsService. You should switch to a secure encoder like BCryptPasswordEncoder for better security.
//Session Management: The application is stateless, which means no sessions are stored on the server, and every request must carry authentication data (suitable for JWT-based systems).