package nextstep.security.userdetails;

import java.util.Set;

public class BaseUser implements UserDetails {

    private final String username;
    private final String password;
    private final Set<String> authorities;

    public BaseUser(
        String username,
        String password,
        Set<String> authorities
    ) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
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
    public Set<String> getAuthorities() {
        return authorities;
    }

}
