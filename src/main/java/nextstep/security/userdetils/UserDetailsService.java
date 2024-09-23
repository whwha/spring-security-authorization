package nextstep.security.userdetils;

public interface UserDetailsService {
    UserDetails loadUserByUsername(String username);
}
