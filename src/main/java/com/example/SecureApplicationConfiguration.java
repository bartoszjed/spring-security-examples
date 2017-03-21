package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static java.util.Collections.singletonList;

@Configuration
@EnableGlobalMethodSecurity()
public class SecureApplicationConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().antMatchers("/secret").hasRole("USER")
                .and()
                .authorizeRequests().antMatchers("/top/secret").hasRole("ADMIN")
                .and().httpBasic();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new CustomAuthenticationProvider());
    }

    public static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (isExternalUser(authentication) && "external_password".equals(authentication.getCredentials())) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        authentication.getPrincipal(),
                        authentication.getCredentials(),
                        singletonList(authentication.getPrincipal().equals("external_user") ? new SimpleGrantedAuthority("ROLE_USER") : new SimpleGrantedAuthority("ROLE_ADMIN")));
                return usernamePasswordAuthenticationToken;
            }
            return null;
        }

        private boolean isExternalUser(Authentication authentication) {
            return authentication.getPrincipal().equals("external_user") ||
                    authentication.getPrincipal().equals("external_admin");
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }
}
