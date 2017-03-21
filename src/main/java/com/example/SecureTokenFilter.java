package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Optional;

public class SecureTokenFilter extends GenericFilterBean {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final AuthenticationManager authenticationManager;

    private static final String HEADER_PREFIX = "customToken";

    public SecureTokenFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            readTokenFrom(httpRequest.getHeader("Authorization"))
                    .map(this::authenticateToken)
                    .ifPresent(this::setAuthenticationInSecurityContext);
        } catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
            SecurityContextHolder.clearContext();
            logger.error("Internal authentication service exception", internalAuthenticationServiceException);
            sendError(httpResponse);
            return;
        } catch (AuthenticationException authenticationException) {
            SecurityContextHolder.clearContext();
            sendError(httpResponse);
            return;
        }

        chain.doFilter(request, response);
    }

    private Optional<String> readTokenFrom(String headerValue) {
        return Optional.ofNullable(headerValue)
                .filter(this::isNotEmpty)
                .filter(this::hasPrefixAndTokenValue)
                .filter(this::hasRightPrefix)
                .map(this::token);
    }

    private boolean isNotEmpty(String headerValue) {
        return headerValue != null;
    }

    private boolean hasPrefixAndTokenValue(String headerValue) {
        int space = headerValue.indexOf(' ');
        return space > 0;
    }

    private boolean hasRightPrefix(String headerValue) {
        String headerValuePrefix = headerValue.substring(0, headerValue.indexOf(' '));
        return HEADER_PREFIX.equalsIgnoreCase(headerValuePrefix);
    }

    private String token(String headerValue) {
        int space = headerValue.indexOf(' ');
        String token = headerValue.substring(space + 1);
        return token;
    }



    private Authentication authenticateToken(String stringToken) {
        SecureToken secureToken = new SecureToken(stringToken);
        Authentication responseAuthentication = authenticationManager.authenticate(secureToken);
        if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
            throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
        }
        logger.debug("User successfully authenticated");
        return responseAuthentication;
    }

    private void setAuthenticationInSecurityContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void sendError(HttpServletResponse httpResponse) throws IOException {
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        httpResponse.setCharacterEncoding("UTF-8");
        PrintWriter writer = httpResponse.getWriter();
        writer.write("{\"error\": \"Auth Error\"}");
        writer.close();
    }
}
