package com.joeladjidan.gestiondestock.config;

import com.joeladjidan.gestiondestock.exception.EntityNotFoundException;
import com.joeladjidan.gestiondestock.services.auth.ApplicationUserDetailsService;
import com.joeladjidan.gestiondestock.utils.JwtUtil;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
public class JwtAuthentificationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";
    public String idEntreprise = "";


    @Autowired
    private JwtUtil jwtUtilService;

    @Autowired
    private ApplicationUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final Optional<String> jwt = getJwtFromRequest(request);
        jwt.ifPresent(token -> {
            try {
                if (jwtUtilService.validateToken(token)) {
                    setSecurityContext(new WebAuthenticationDetailsSource().buildDetails(request), token);
                }
            } catch (IllegalArgumentException | JwtException e) {
                logger.error("Unable to get JWT Token or JWT Token has expired");
                SecurityContextHolder.clearContext();
                // most likely an ExpiredJwtException, but this will handle any
                request.setAttribute("exception", e);
                request.setAttribute("expired-jwt", e);
                RequestDispatcher dispatcher = request.getRequestDispatcher("expired-jwt");
                try {
                   dispatcher.forward(request, response);
                   throw new EntityNotFoundException("" + e.getMessage());
                } catch (ServletException e1) {
                    e1.printStackTrace();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        });

        MDC.put("idEntreprise", idEntreprise);
        filterChain.doFilter(request, response);

    }

    private void setSecurityContext(WebAuthenticationDetails authDetails, String token) {
        final String username = jwtUtilService.extractUsername(token);
        idEntreprise = jwtUtilService.extractIdEntreprise(token);
        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                userDetails.getAuthorities());
        authentication.setDetails(authDetails);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static Optional<String> getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER)) {
            return Optional.of(bearerToken.substring(7));
        }
        return Optional.empty();
    }

}
