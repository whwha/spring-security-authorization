package nextstep.security.userdetails;

import nextstep.security.exception.AuthenticationException;

public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws AuthenticationException;
}
