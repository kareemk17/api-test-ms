package com.example.api_test.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;



public class ApiKeyAuthFilter extends AbstractAuthenticationProcessingFilter {

    private static final String API_KEY_HEADER = "YWVzMjREY2JjMTkyQklWMA";
    private static final String API_SECRET_HEADER = "4O5wscDWe/WNnvBWLicQICdlltdvp6hVoFqKWl8fKEJWuAv2U/bCydhRSV77CcERdUSJtJ5crRp755beJt66wkrz0ghS2fAW06mxyGFN9xo=";

    public ApiKeyAuthFilter(RequestMatcher requiresAuth) {
        super(requiresAuth);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        String apiKey = request.getHeader(API_KEY_HEADER);
        String apiSecret = request.getHeader(API_SECRET_HEADER);

        if (apiKey == null || apiSecret == null) {
            throw new RuntimeException("Missing API Key or Secret");
        }

        Authentication auth = new ApiKeyAuthenticationToken(apiKey, apiSecret);
        return getAuthenticationManager().authenticate(auth);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }
}
