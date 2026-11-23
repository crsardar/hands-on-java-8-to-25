package com.crsardar.java.user;

import java.util.List;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Changes account status at runtime, e.g. disable a user who still holds a valid token.
 *
 * <p>Demo only: any authenticated user may call it (this example has no roles).
 * A real application would restrict who can change another account's status.
 */
@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "Account status (demo: any valid token)")
@ApiResponse(responseCode = "401", description = "Missing or invalid token")
public class UserController {

    public record UserView(String username, AccountStatus status) {
        static UserView of(UserAccount account) {
            return new UserView(account.username(), account.status());
        }
    }

    public record StatusChange(@NotNull AccountStatus status) {
    }

    private final UserAccountRepository repository;

    public UserController(UserAccountRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    @Operation(summary = "List all accounts and their status")
    public List<UserView> list() {
        return repository.findAll().stream().map(UserView::of).toList();
    }

    @PatchMapping("/{username}/status")
    @Operation(summary = "Change account status; tokens of a non-ACTIVE account are rejected from the next request")
    @ApiResponse(responseCode = "200", description = "Status changed")
    @ApiResponse(responseCode = "404", description = "No such user")
    public ResponseEntity<UserView> changeStatus(@PathVariable String username,
                                                 @Valid @RequestBody StatusChange change) {
        return ResponseEntity.of(repository.updateStatus(username, change.status()).map(UserView::of));
    }
}
