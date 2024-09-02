package io.github.innobridge.security.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import io.github.innobridge.security.model.User;

@Repository
public interface UserRepository extends MongoRepository<User, String>, CustomUserRepository {
    
        // Custom query to find employees by firstname
    @Query("{ 'username' : ?0 }")
    Optional<User> findByUsername(String username);

    @Query("{ 'email' : ?0 }")
    Optional<User> findByEmail(String email);

}
