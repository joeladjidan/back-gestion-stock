package com.joeladjidan.gestiondestock.controller;


import com.joeladjidan.gestiondestock.controller.api.AuthenticationApi;
import com.joeladjidan.gestiondestock.dto.auth.AuthenticationRequest;
import com.joeladjidan.gestiondestock.dto.auth.AuthenticationResponse;
import com.joeladjidan.gestiondestock.model.auth.ExtendedUser;
import com.joeladjidan.gestiondestock.services.auth.ApplicationUserDetailsService;
import com.joeladjidan.gestiondestock.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
@Validated
@Slf4j
public class AuthenticationController implements AuthenticationApi {

  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private ApplicationUserDetailsService userDetailsService;

  @Autowired
  private JwtUtil jwtUtil;

  @Override
  public ResponseEntity<AuthenticationResponse> authenticate(AuthenticationRequest request) throws Exception {
	  log.info("AuthenticationResponse is request {}", request);

    authenticate(request.getLogin(), request.getPassword());

    final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getLogin());

    final String jwt = jwtUtil.generateToken((ExtendedUser) userDetails);

    log.info("AuthenticationResponse is jwt {}", jwt);

    log.info("AuthenticationResponse is login {}", request.getLogin());

    log.info("AuthenticationResponse is password {}", request.getPassword());

    return ResponseEntity.ok(AuthenticationResponse.builder().accessToken(jwt).build());
  }

  private void authenticate(String username, String password) throws Exception {
    Objects.requireNonNull(username);
    Objects.requireNonNull(password);
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    } catch (DisabledException e) {
      throw new Exception("USER_DISABLED", e);
    } catch (BadCredentialsException e) {
      throw new Exception("INVALID_CREDENTIALS", e);
    }
  }
}
