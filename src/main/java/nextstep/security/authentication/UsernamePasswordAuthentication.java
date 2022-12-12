package nextstep.security.authentication;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class UsernamePasswordAuthentication implements Authentication {
    private final String username;
    private final String password;
    private boolean authenticated = false;
    private final Set<String> authorities;

    private UsernamePasswordAuthentication(String username, String password, Set<String> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    public static UsernamePasswordAuthentication ofAuthenticated(
            String username,
            String password,
            Set<String> authorities
    ) {
        UsernamePasswordAuthentication authentication
                = new UsernamePasswordAuthentication(username, password, authorities);
        authentication.authenticated = true;
        return authentication;
    }

    public static UsernamePasswordAuthentication ofRequest(
            String username,
            String password
    ) {
        Set<String> defaultAuthorities = Set.of();
        return new UsernamePasswordAuthentication(username, password, defaultAuthorities);
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    @Override
    public Set<String> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

}
