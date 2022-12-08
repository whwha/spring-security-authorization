package nextstep.security.authentication;

import java.util.Set;

public interface Authentication {
    Object getPrincipal();

    Object getCredentials();

    Set<String> getAuthorities();

    boolean isAuthenticated();
}
