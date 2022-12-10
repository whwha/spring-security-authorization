package nextstep.security.config;

import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.fixture.MockFilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class FilterChainProxyTest {
    private FilterChainProxy filterChainProxy;
    private TestFilter loginTestFilter;
    private TestFilter membersTestFilter;

    @BeforeEach
    void setUp() {
        loginTestFilter = new TestFilter();
        SecurityFilterChain loginFilterChain = new DefaultSecurityFilterChain(
                new MvcRequestMatcher(HttpMethod.POST, "/login"),
                List.of(loginTestFilter)
        );

        membersTestFilter = new TestFilter();
        SecurityFilterChain membersFilterChain = new DefaultSecurityFilterChain(
                new MvcRequestMatcher(HttpMethod.GET, "/members"),
                List.of(membersTestFilter)
        );

        filterChainProxy = new FilterChainProxy(List.of(loginFilterChain, membersFilterChain));
    }

    @Test
    void login() throws ServletException, IOException {
        HttpServletRequest request = new MockHttpServletRequest(HttpMethod.POST.name(), "/login");
        filterChainProxy.doFilter(request, null, null);

        assertThat(loginTestFilter.count).isEqualTo(1);
        assertThat(membersTestFilter.count).isZero();
    }

    @Test
    void members() throws ServletException, IOException {
        HttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "/members");
        filterChainProxy.doFilter(request, null, null);

        assertThat(loginTestFilter.count).isZero();
        assertThat(membersTestFilter.count).isEqualTo(1);
    }

    @Test
    void none() throws ServletException, IOException {
        HttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "/test");
        filterChainProxy.doFilter(request, null, new MockFilterChain());


        assertThat(loginTestFilter.count).isZero();
        assertThat(membersTestFilter.count).isZero();
    }

    private static class TestFilter implements Filter {
        private int count = 0;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            count++;
        }
    }
}
