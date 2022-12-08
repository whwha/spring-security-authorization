package nextstep.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.fixture.MockFilterChain;
import nextstep.security.fixture.TestUserDetailsService;
import nextstep.security.fixture.TestUserInmemoryRepository;
import nextstep.security.userdetails.UserDetailsService;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class BasicAuthenticationFilterTest {
    private static final Member TEST_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;
    private BasicAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        UserDetailsService userDetailsService = new TestUserDetailsService(new TestUserInmemoryRepository());
        AuthenticationProvider provider = new UsernamePasswordAuthenticationProvider(userDetailsService);
        AuthenticationManager authenticationManager = new AuthenticationManager(provider);
        filter = new BasicAuthenticationFilter(authenticationManager, new HttpSessionSecurityContextRepository());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void success() throws Exception {
        filter.doFilter(createMockAuthenticationRequestWith(TEST_MEMBER.getEmail(), TEST_MEMBER.getPassword()), null, new MockFilterChain());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.getPrincipal()).isEqualTo(TEST_MEMBER.getEmail());
        assertThat(authentication.getCredentials()).isEqualTo(TEST_MEMBER.getPassword());
    }

    @Test
    void fail() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(createMockAuthenticationRequestWith(TEST_MEMBER.getEmail(), "invalid"), response, new MockFilterChain());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    private MockHttpServletRequest createMockAuthenticationRequestWith(String username, String password) {
        MockHttpServletRequest request = new MockHttpServletRequest();

        String token = Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + token);

        return request;
    }
}
