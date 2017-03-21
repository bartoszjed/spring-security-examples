package com.example;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Arrays;

public class SecureToken extends AbstractAuthenticationToken {
    private final String value;

    public SecureToken(String tokenValue) {
        super(Arrays.asList());
        value = tokenValue;
    }

    public SecureToken(String tokenValue, String... roles) {
        super(AuthorityUtils.createAuthorityList(roles));
        value = tokenValue;
        super.setAuthenticated(true);
    }

    //Getters and Constructor.  Make sure getAutheticated returns false at first.
    //I made mine "immutable" via:

    @Override
    public Object getCredentials() {
        return "NO_CREDENTIALS";
    }

    @Override
    public Object getPrincipal() {
        return value;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("MESSAGE_CANNOT_SET_AUTHENTICATED");
        }
        super.setAuthenticated(false);
    }
}
