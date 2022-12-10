package nextstep.security.fixture;

import nextstep.security.exception.AuthenticationException;
import nextstep.security.userdetails.UserDetails;
import nextstep.security.userdetails.UserDetailsService;

public class TestUserDetailsService implements UserDetailsService {
    private final TestUserInMemoryRepository testUserInmemoryRepository;

    public TestUserDetailsService(TestUserInMemoryRepository testUserInmemoryRepository) {
        this.testUserInmemoryRepository = testUserInmemoryRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws AuthenticationException {
        return testUserInmemoryRepository.findByUsername(username)
                .orElseThrow(AuthenticationException::new);
    }
}
