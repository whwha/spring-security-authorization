package nextstep.security.authentication;

public class UsernamePasswordAuthenticationToken implements Authentication {
    private final String principal;
    private final String credentials;
    private final boolean authenticated;

    private UsernamePasswordAuthenticationToken(String principal, String credentials, boolean authenticated) {
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = authenticated;
    }

    public static UsernamePasswordAuthenticationToken unauthenticated(String principal, String credentials) {
        return new UsernamePasswordAuthenticationToken(principal, credentials, false);
    }

    public static UsernamePasswordAuthenticationToken authenticated(String principal, String credentials) {
        return new UsernamePasswordAuthenticationToken(principal, credentials, true);
    }

    @Override
    public String getCredentials() {
        return credentials;
    }

    @Override
    public String getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }
}
