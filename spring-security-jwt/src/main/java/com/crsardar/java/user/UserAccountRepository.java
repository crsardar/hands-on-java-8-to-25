package com.crsardar.java.user;

import java.util.List;
import java.util.Optional;

/**
 * Access to the user table. Swap {@link InMemoryUserAccountRepository} for a JPA/JDBC/MyBatis
 * implementation and nothing else in the security setup changes.
 */
public interface UserAccountRepository {

    Optional<UserAccount> findByUsername(String username);

    List<UserAccount> findAll();

    Optional<UserAccount> updateStatus(String username, AccountStatus status);
}
