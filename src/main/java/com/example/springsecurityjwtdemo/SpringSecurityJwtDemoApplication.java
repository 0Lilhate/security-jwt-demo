package com.example.springsecurityjwtdemo;

import com.example.springsecurityjwtdemo.domain.Person;
import com.example.springsecurityjwtdemo.domain.Role;
import com.example.springsecurityjwtdemo.domain.StatusPerson;
import com.example.springsecurityjwtdemo.service.PersonService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtDemoApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner runner(PersonService personService){
		return args -> {
			personService.saveRoel(new Role(null, "ROLE_USER"));
			personService.saveRoel(new Role(null, "ROLE_MANAGER"));
			personService.saveRoel(new Role(null, "ROLE_ADMIN"));
			personService.saveRoel(new Role(null, "ROLE_SUPER_ADMIN"));

			personService.savePerson(new Person(null, "0804@gmail.com", "admin",
					StatusPerson.ONLINE, new ArrayList<>()));
			personService.savePerson(new Person(null, "egor@gmail.com", "egor",
					StatusPerson.ONLINE, new ArrayList<>()));
			personService.savePerson(new Person(null, "anstasia@gmail.com", "user",
					StatusPerson.ONLINE, new ArrayList<>()));
			personService.savePerson(new Person(null, "dima@gmail.com", "user",
					StatusPerson.ONLINE, new ArrayList<>()));

			personService.addRoleToPerson("0804@gmail.com", "ROLE_SUPER_ADMIN");
			personService.addRoleToPerson("0804@gmail.com", "ROLE_ADMIN");
			personService.addRoleToPerson("0804@gmail.com", "ROLE_USER");

			personService.addRoleToPerson("egor@gmail.com", "ROLE_ADMIN");
			personService.addRoleToPerson("anstasia@gmail.com", "ROLE_MANAGER");
			personService.addRoleToPerson("dima@gmail.com", "ROLE_USER");
		};
	}


}
