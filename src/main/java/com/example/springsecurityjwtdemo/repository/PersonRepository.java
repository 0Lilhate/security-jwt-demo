package com.example.springsecurityjwtdemo.repository;



import com.example.springsecurityjwtdemo.domain.Person;
import org.springframework.data.jpa.repository.JpaRepository;


public interface PersonRepository extends JpaRepository<Person, Long> {
    Person findByEmail(String email);

}
