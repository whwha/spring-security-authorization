package nextstep.security.userdetails;

import java.util.Set;

public class BaseUser implements UserDetails {

    private final String username;
    private final String password;
    private final Set<String> roles;

    public BaseUser(String username, String password, Set<String> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
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
    public Set<String> getRoles() { return roles; }

}
