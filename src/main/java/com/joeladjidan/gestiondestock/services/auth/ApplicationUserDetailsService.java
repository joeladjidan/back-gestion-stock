package com.joeladjidan.gestiondestock.services.auth;

import com.joeladjidan.gestiondestock.dto.UtilisateurDto;
import com.joeladjidan.gestiondestock.exception.EntityNotFoundException;
import com.joeladjidan.gestiondestock.exception.ErrorCodes;
import com.joeladjidan.gestiondestock.model.auth.ExtendedUser;
import com.joeladjidan.gestiondestock.services.UtilisateurService;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ApplicationUserDetailsService implements UserDetailsService {

  @Autowired
  private UtilisateurService service;


  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    log.info("Beggin loadUserByUsername is email {}", email);

    UtilisateurDto utilisateur = service.findByEmail(email);

      if (utilisateur != null) {
          log.info("utilisateur role size {}", utilisateur.getRoles().size());

          List<SimpleGrantedAuthority> authorities = new ArrayList<>();
          utilisateur.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getRoleName())));

          ExtendedUser extendedUser = new ExtendedUser(utilisateur.getEmail(), utilisateur.getMoteDePasse(), utilisateur.getEntreprise().getId(), authorities);

          log.info("extendedUser is {}", extendedUser);

          log.info("End loadUserByUsername successfully");

          return extendedUser;
      } else {
          throw new UsernameNotFoundException("User not found with email: " + email);
      }
  }
}
