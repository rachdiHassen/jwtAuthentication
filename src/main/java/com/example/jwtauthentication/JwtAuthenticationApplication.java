package com.example.jwtauthentication;

import com.example.jwtauthentication.security.entities.AppUser;
import com.example.jwtauthentication.security.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class JwtAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationApplication.class, args);
	}

	@Bean
	CommandLineRunner start(AccountService accountService){
		return args -> {
			accountService.addNewUser(new AppUser(null,"hassen","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"habiba","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"samira","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"joud","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"bassem","123",new ArrayList<>()));


			accountService.addNewRole("ADMIN");
			accountService.addNewRole("USER");
			accountService.addNewRole("CUSTOMER_MANAGER");
			accountService.addNewRole("PRODUCT_MANAGER");
			accountService.addNewRole("BILLS_MANAGER");

			accountService.addRoleToUser("hassen","USER");
			accountService.addRoleToUser("habiba","USER");
			accountService.addRoleToUser("samira","USER");
			accountService.addRoleToUser("habiba","ADMIN");
		};
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

}
