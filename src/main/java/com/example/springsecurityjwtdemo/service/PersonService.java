package com.example.springsecurityjwtdemo.service;



import com.example.springsecurityjwtdemo.domain.Person;
import com.example.springsecurityjwtdemo.domain.Role;

import java.util.List;

public interface PersonService {
    Person savePerson(Person person);
    Role saveRoel(Role role);
    List<Role> getRoles();
    void addRoleToPerson(String email, String roleName);
    Person getPerson(String email);
    List<Person> getPersons();
}
