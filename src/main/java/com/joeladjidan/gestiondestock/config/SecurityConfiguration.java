package com.joeladjidan.gestiondestock.config;

import java.util.Arrays;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.joeladjidan.gestiondestock.services.auth.ApplicationUserDetailsService;

@EnableWebSecurity(debug = false)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	// npm install --save --legacy-peer-deps
  //  http://localhost:8081/swagger-ui/index.html

  @Autowired
  private ApplicationUserDetailsService applicationUserDetailsService;

  @Autowired
  @Qualifier("jwtAuthenticationEntryPoint")
  AuthenticationEntryPoint authenticationEntryPoint;

  @Autowired private JwtAuthentificationFilter jwtAuthentificationFilter;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.userDetailsService(applicationUserDetailsService).passwordEncoder(passwordEncoder());
  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // Set session management to stateless
    http = http.addFilter(corsFilter()).csrf().disable()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint)
            .and();

    // Set permissions on endpoints
    http.authorizeRequests()
    .antMatchers("/**/authenticate/**",
            "/**/entreprises/create",
            "/**/utilisateurs/**",
            "/**/clients",
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**",
            "/v3/api-docs/**",
            "/swagger-ui/**").permitAll()
            .anyRequest().authenticated();

    // Add JWT token filter
    http.addFilterBefore(jwtAuthentificationFilter, UsernamePasswordAuthenticationFilter.class);
}

// Used by spring security if CORS is enabled.
  @Bean
  public CorsFilter corsFilter() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    final CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    // Don't do this in production, use a proper list  of allowed origins
    config.setAllowedOriginPatterns(Collections.singletonList("*"));
    config.setAllowedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "Authorization", "RefreshToken"));
    config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
  }

  @Bean
  public AuthenticationManager customAuthenticationManager() throws Exception {
    return authenticationManagerBean();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
	  return new BCryptPasswordEncoder();
  }
}
