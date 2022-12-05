package nextstep.security.authentication;

public class UsernamePasswordAuthentication implements Authentication {
    private final String username;
    private final String password;
    private boolean authenticated = false;

    private UsernamePasswordAuthentication(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public static UsernamePasswordAuthentication ofAuthenticated(String username, String password) {
        UsernamePasswordAuthentication authentication = new UsernamePasswordAuthentication(username, password);
        authentication.authenticated = true;
        return authentication;
    }

    public static UsernamePasswordAuthentication ofRequest(String username, String password) {
        return new UsernamePasswordAuthentication(username, password);
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
    public boolean isAuthenticated() {
        return authenticated;
    }

}
