package nextstep.security.userdetails;

import nextstep.security.authentication.Role;

import java.util.Set;
import java.util.stream.Collectors;

public class BaseUser implements UserDetails {

    private final String username;
    private final String password;
    private final Set<Role> roles;

    public BaseUser(String username, String password, Role... roles) {
        this.username = username;
        this.password = password;
        this.roles = Set.of(roles);
    }

    public BaseUser(String username, String password, Set<String> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles.stream()
                .map(Role::valueOf)
                .collect(Collectors.toSet());
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Set<Role> getRoles() {
        return roles;
    }
}
