package com.joeladjidan.gestiondestock;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.joeladjidan.gestiondestock.model.Adresse;
import com.joeladjidan.gestiondestock.model.Category;
import com.joeladjidan.gestiondestock.model.Client;
import com.joeladjidan.gestiondestock.model.Entreprise;
import com.joeladjidan.gestiondestock.model.Roles;
import com.joeladjidan.gestiondestock.model.Utilisateur;
import com.joeladjidan.gestiondestock.repository.CategoryRepository;
import com.joeladjidan.gestiondestock.repository.ClientRepository;
import com.joeladjidan.gestiondestock.repository.EntrepriseRepository;
import com.joeladjidan.gestiondestock.repository.RolesRepository;
import com.joeladjidan.gestiondestock.repository.UtilisateurRepository;

@SpringBootApplication
@EnableJpaAuditing
public class ApiGestionDeStockApplication {

	// https://javainfinite.com/springsecurity/spring-boot-security-with-jwt-example-token-generate-validate-and-refresh/

  public static void main(String[] args) {
    SpringApplication.run(ApiGestionDeStockApplication.class, args);
  }

  @Component
  class DBInitCommandLineRunner implements CommandLineRunner{

  	@Autowired
  	private UtilisateurRepository utilisateurRepository;

  	@Autowired
  	private EntrepriseRepository entrepriseRepository;

	@Autowired
  	private ClientRepository clientRepository;

	@Autowired
  	private RolesRepository roleRepository;

	@Autowired
  	private CategoryRepository categoryRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

  	@SuppressWarnings("deprecation")
	@Override
  	public void run(String... args) throws Exception {
  		Entreprise entrepriseRs = null;
  		Utilisateur utilisateurRs = null;

  		Adresse adresse = new Adresse();
  		adresse.setPays("FRANCE");
  		adresse.setCodePostale("94400");
  		adresse.setAdresse1("67 Avenue Jean Jaures");
  		adresse.setVille("VITRY-SUR-SEINE");

  		Category category = new Category();
  		category.setId(1);
  		category.setIdEntreprise(1);
  		category.setCode("A123456");
  		category.setLastModifiedDate(new Date().toInstant());
  		category.setCreationDate(new Date().toInstant());

  		if(categoryRepository.findAll().isEmpty())
  		   categoryRepository.save(category);

  		Client client = new Client();
  		client.setId(1);
  		client.setAdresse(adresse);
  		client.setIdEntreprise(1);
  		client.setNom("ADJIDAN");
  		client.setPrenom("INES");
  		client.setMail("joeladjidan@gmail.com");
  		client.setLastModifiedDate(new Date().toInstant());
  		client.setCreationDate(new Date().toInstant());

  		if(clientRepository.findAll().isEmpty())
  		   clientRepository.save(client);

  		Entreprise entreprise = new Entreprise();
  		entreprise.setNom("ANSGROUP");
  		entreprise.setAdresse(adresse);
  		entreprise.setCodeFiscal("123456789");
  		entreprise.setNumTel("+330650599343");
  		entreprise.setEmail("ansgroup@gmail.com");
  		entreprise.setCreationDate(new Date().toInstant());
  		entreprise.setLastModifiedDate(new Date().toInstant());

  		if(entrepriseRepository.findAll().isEmpty()) {
  			entrepriseRs = entrepriseRepository.save(entreprise);
  		}


  		Utilisateur utulisateur = new Utilisateur();
  		utulisateur.setLastModifiedDate(new Date().toInstant());
  		utulisateur.setCreationDate(new Date().toInstant());
  		utulisateur.setPrenom("Joel");
  		utulisateur.setDateDeNaissance(new Date(1986,03,26).toInstant());
  		utulisateur.setEmail("joeladjidan@gmail.com");
  		utulisateur.setNom("ADJIDAN");
  		utulisateur.setAdresse(adresse);
  		utulisateur.setEntreprise(entrepriseRs);
  		utulisateur.setMoteDePasse(passwordEncoder.encode("Ines26031986*"));

  		if(utilisateurRepository.findAll().isEmpty())
  		   utilisateurRs = utilisateurRepository.save(utulisateur);

  		Roles role = new Roles();
  		role.setRoleName("ADMIN");
  		role.setUtilisateur(utilisateurRs);
  		role.setCreationDate(new Date().toInstant());
  		role.setLastModifiedDate(new Date().toInstant());

  		if(roleRepository.findAll().isEmpty())
  		   roleRepository.save(role);

  	}
  }
}
