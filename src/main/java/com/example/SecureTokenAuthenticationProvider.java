package com.example;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class SecureTokenAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication.getPrincipal().equals("MY_SECRET_TOKEN")) {
            return new SecureToken((String)authentication.getPrincipal(), "ROLE_USER", "ROLE_ADMIN");
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecureToken.class.equals(authentication);
    }
}
