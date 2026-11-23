package com.crsardar.java.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Login (POST /api/auth/token) reads from the same user table.
 * DaoAuthenticationProvider rejects disabled/locked accounts, so they never get a token.
 */
@Service
public class UserAccountDetailsService implements UserDetailsService {

    private final UserAccountRepository repository;

    public UserAccountDetailsService(UserAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserAccount account = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        return User.withUsername(account.username())
                .password(account.passwordHash())
                .disabled(account.status() == AccountStatus.DISABLED)
                .accountLocked(account.status() == AccountStatus.LOCKED)
                .build();
    }
}
