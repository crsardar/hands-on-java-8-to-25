package com.crsardar.java.user;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

/** Stand-in for the DB user table: a predefined set of accounts, mutable at runtime. */
@Repository
public class InMemoryUserAccountRepository implements UserAccountRepository {

    private final Map<String, UserAccount> table = new ConcurrentHashMap<>();

    public InMemoryUserAccountRepository(PasswordEncoder encoder) {
        save(new UserAccount("crsardar", encoder.encode("Chitta@123"), List.of("USER"), AccountStatus.ACTIVE));
        save(new UserAccount("admin", encoder.encode("admin123"), List.of("USER", "ADMIN"), AccountStatus.ACTIVE));
        save(new UserAccount("bob", encoder.encode("bob123"), List.of("USER"), AccountStatus.DISABLED));
    }

    private void save(UserAccount account) {
        table.put(account.username(), account);
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(table.get(username));
    }

    @Override
    public List<UserAccount> findAll() {
        return table.values().stream()
                .sorted(Comparator.comparing(UserAccount::username))
                .toList();
    }

    @Override
    public Optional<UserAccount> updateStatus(String username, AccountStatus status) {
        return Optional.ofNullable(table.computeIfPresent(username, (_, account) -> account.withStatus(status)));
    }
}
