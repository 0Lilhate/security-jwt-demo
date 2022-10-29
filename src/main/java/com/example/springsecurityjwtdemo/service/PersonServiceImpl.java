package com.example.springsecurityjwtdemo.service;


import com.example.springsecurityjwtdemo.domain.Person;
import com.example.springsecurityjwtdemo.domain.Role;
import com.example.springsecurityjwtdemo.repository.PersonRepository;
import com.example.springsecurityjwtdemo.repository.RoleRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;



@Service
@AllArgsConstructor
public class PersonServiceImpl implements PersonService, UserDetailsService {

    private final PersonRepository personRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Person person = personRepository.findByEmail(username);
        if(person==null){
            throw new UsernameNotFoundException("User not found datebase");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        person.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new User(person.getEmail(), person.getPassword(), authorities);
    }



    @Override
    public Person savePerson(Person person) {

        person.setPassword(passwordEncoder.encode(person.getPassword()));
        return personRepository.save(person);
    }

    @Override
    public Role saveRoel(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    @Transactional
    @Override
    public void addRoleToPerson(String email, String roleName) {
        Person person = personRepository.findByEmail(email);
        Role role = roleRepository.findByName(roleName);
        person.getRoles().add(role);
        personRepository.save(person);
    }

    @Override
    public Person getPerson(String email) {
        return personRepository.findByEmail(email);
    }

    @Override
    public List<Person> getPersons() {
        return personRepository.findAll();
    }


}
