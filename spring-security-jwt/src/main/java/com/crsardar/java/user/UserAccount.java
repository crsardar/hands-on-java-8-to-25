package com.crsardar.java.user;

import java.util.List;

/** One row of the user table. */
public record UserAccount(String username, String passwordHash, List<String> roles, AccountStatus status) {

    public boolean isActive() {
        return status == AccountStatus.ACTIVE;
    }

    public UserAccount withStatus(AccountStatus newStatus) {
        return new UserAccount(username, passwordHash, roles, newStatus);
    }
}
