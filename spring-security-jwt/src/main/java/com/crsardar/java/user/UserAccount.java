package com.crsardar.java.user;

/** One row of the user table. */
public record UserAccount(String username, String passwordHash, AccountStatus status) {

    public boolean isActive() {
        return status == AccountStatus.ACTIVE;
    }

    public UserAccount withStatus(AccountStatus newStatus) {
        return new UserAccount(username, passwordHash, newStatus);
    }
}
