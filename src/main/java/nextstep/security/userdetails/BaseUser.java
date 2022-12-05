package nextstep.security.userdetails;

public class BaseUser implements UserDetails{

    private final String username;
    private final String password;

    public BaseUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

}
