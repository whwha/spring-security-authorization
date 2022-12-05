package nextstep.security.authentication;

public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication);

    boolean supports(Class<?> authentication);
}
