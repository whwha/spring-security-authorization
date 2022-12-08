package nextstep.security.authorization;

import java.util.Set;

public class RoleManager {

    private final Set<String> roles;

    public RoleManager(Set<String> roles) {
        this.roles = roles;
    }

    public RoleManager(String... roles) {
        this(Set.of(roles));
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
