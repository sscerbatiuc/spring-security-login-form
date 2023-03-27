package org.example.securitydemo.repository;

import java.util.Optional;

import org.example.securitydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findUserByUsername(String username);
}
