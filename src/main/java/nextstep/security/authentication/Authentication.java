package nextstep.security.authentication;

import java.util.Set;

public interface Authentication {
    Set<String> getAuthorities();

    Object getCredentials();

    Object getPrincipal();

    boolean isAuthenticated();
}
