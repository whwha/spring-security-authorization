package nextstep.security.authentication;

import nextstep.security.userdetils.UserDetails;
import nextstep.security.userdetils.UserDetailsService;

public class DaoAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getPrincipal().toString());
        if (userDetails == null) {
            throw new AuthenticationException();
        }

        if (!userDetails.getPassword().equals(authentication.getCredentials())) {
            throw new AuthenticationException();
        }

        return UsernamePasswordAuthenticationToken.authenticated(userDetails.getUsername(), userDetails.getPassword());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
