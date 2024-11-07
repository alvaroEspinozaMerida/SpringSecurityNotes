package com.espinozameridaal.securityexnotes.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

public class UserPrincipal implements UserDetails {

//    Users user: This is an instance of your custom Users entity.
//    It contains all the user details, such as the username, password,
//    and potentially additional information like roles or account status.

//This user object is passed into the constructor when the UserPrincipal object
// is created. The fields of this user will be used to fulfill the contract
// required by UserDetails.

    private Users user;

//    The constructor accepts an instance of the Users entity.
//    This allows the UserPrincipal class to access the user’s information
//    (username, password, etc.) and provide that information to Spring Security
//    when needed.

    public UserPrincipal(Users user) {
        this.user = user;
    }

//    Purpose: This method returns the authorities (roles or permissions) granted to the user.
//    In this case, you are returning a single authority "USER".
//
//Security Role: The roles or permissions returned here are used by Spring Security for authorization purposes
// (to restrict access to certain parts of your application). This means that any user authenticated using this
// UserPrincipal will have the role USER.
//
//Improvement: If your Users entity has a dynamic role or authority structure
// (e.g., users can have multiple roles like ADMIN, USER, etc.),
// you should return a collection of roles from the database.

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority("USER"));
    }

//    Purpose: This method returns the user's password, which is necessary for authentication.
//    Spring Security uses this password to compare against the password the user provides when they try to log in.
//
//Security Note: Ensure that the password stored in your Users entity is hashed
// (e.g., using BCrypt). Never store plain-text passwords in the database.

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    //Purpose: This method returns the username, which is used to identify the user during authentication.
    @Override
    public String getUsername() {
        return user.getUsername();
    }


//    These methods allow you to control the status of a user’s account.
//    By returning true for all these methods, you're essentially indicating that the user's account is active and valid.
//
//isAccountNonExpired():
//This checks if the user's account has expired. Returning true means the account is still valid.

//isAccountNonLocked():
//This checks if the user’s account is locked. Returning true means the account is not locked and is available for use.

//isCredentialsNonExpired():
//This checks if the user's credentials (password) have expired. Returning true means the credentials are valid.

//isEnabled():
//This checks if the user’s account is enabled. Returning true means the account is active.
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
