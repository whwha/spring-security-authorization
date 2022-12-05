package nextstep.security.authentication;

import nextstep.security.exception.AuthenticationException;

import java.util.Arrays;
import java.util.List;

public class AuthenticationManager {
    private final List<AuthenticationProvider> authenticationProviders;

    public AuthenticationManager(AuthenticationProvider... authenticationProviders) {
        this.authenticationProviders = Arrays.asList(authenticationProviders);
    }

    public Authentication authenticate(Authentication authRequest) {
        for (AuthenticationProvider authenticationProvider : authenticationProviders) {
            if (authenticationProvider.supports(authRequest.getClass())) {
                return authenticationProvider.authenticate(authRequest);
            }
        }

        throw new AuthenticationException();
    }
}
