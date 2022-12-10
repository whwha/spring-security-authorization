package nextstep.security.authentication;

import java.util.Set;
import java.util.stream.Collectors;

public class UsernamePasswordAuthentication implements Authentication {
    private final String username;
    private final String password;
    private final Set<Role> authorities;
    private boolean authenticated = false;

    private UsernamePasswordAuthentication(String username, String password, Set<Role> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    public static UsernamePasswordAuthentication ofAuthenticated(String username, String password, Set<Role> authorities) {
        UsernamePasswordAuthentication authentication = new UsernamePasswordAuthentication(username, password, authorities);
        authentication.authenticated = true;
        return authentication;
    }

    public static UsernamePasswordAuthentication ofRequest(String username, String password) {
        return new UsernamePasswordAuthentication(username, password, Set.of());
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
        return authorities.stream()
                .map(Enum::name)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

}
