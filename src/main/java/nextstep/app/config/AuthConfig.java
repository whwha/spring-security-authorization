package nextstep.app.config;

import nextstep.security.access.matcher.AnyRequestMatcher;
import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.authentication.*;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.userdetails.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class AuthConfig implements WebMvcConfigurer {

    private final UserDetailsService userDetailsService;

    public AuthConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public DelegatingFilterProxy securityFilterChainProxy() {
        return new DelegatingFilterProxy("filterChainProxy");
    }

    @Bean
    public FilterChainProxy filterChainProxy() {
        return new FilterChainProxy(List.of(
                loginSecurityFilterChain(),
                getMembersAuthorizationSecurityFilterChain()
            )
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain() {
        List<Filter> filters = new ArrayList<>();
        filters.add(new UsernamePasswordAuthenticationFilter(authenticationManager(), securityContextRepository()));
        filters.add(new BasicAuthenticationFilter(authenticationManager()));
        return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, filters);
    }

    @Bean
    public SecurityFilterChain loginSecurityFilterChain() {
        MvcRequestMatcher LOGIN_REQUEST_MATCHER = new MvcRequestMatcher(HttpMethod.POST, "/login");

        List<Filter> filters = new ArrayList<>();
        filters.add(new UsernamePasswordAuthenticationFilter(authenticationManager(), securityContextRepository()));

        return new DefaultSecurityFilterChain(LOGIN_REQUEST_MATCHER, filters);
    }

    @Bean
    public SecurityFilterChain getMembersAuthorizationSecurityFilterChain() {
        MvcRequestMatcher MEMBERS_REQUEST_MATCHER = new MvcRequestMatcher(HttpMethod.GET, "/members");
        String ROLE_NAME = "ADMIN";

        List<Filter> filters = new ArrayList<>();
        filters.add(new BasicAuthenticationFilter(authenticationManager()));
        filters.add(new AuthorizationFilter(ROLE_NAME, securityContextRepository()));

        return new DefaultSecurityFilterChain(MEMBERS_REQUEST_MATCHER, filters);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new AuthenticationManager(new UsernamePasswordAuthenticationProvider(userDetailsService));
    }

}
