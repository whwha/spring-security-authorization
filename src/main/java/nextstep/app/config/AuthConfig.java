package nextstep.app.config;

import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.authentication.*;
import nextstep.security.authorization.LoginAuthorizationFilter;
import nextstep.security.authorization.RoleAuthorizationFilter;
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
        return new FilterChainProxy(List.of(loginSecurityFilterChain(), membersSecurityFilterChain()));
    }

    @Bean
    public SecurityFilterChain loginSecurityFilterChain() {
        List<Filter> filters = new ArrayList<>();
        filters.add(new UsernamePasswordAuthenticationFilter(authenticationManager(), securityContextRepository()));
        return new DefaultSecurityFilterChain(new MvcRequestMatcher(HttpMethod.POST, "/login"), filters);
    }

    @Bean
    public SecurityFilterChain membersSecurityFilterChain() {
        List<Filter> filters = new ArrayList<>();
        filters.add(new BasicAuthenticationFilter(authenticationManager()));
        filters.add(new LoginAuthorizationFilter(securityContextRepository()));
        filters.add(new RoleAuthorizationFilter());
        return new DefaultSecurityFilterChain(new MvcRequestMatcher(HttpMethod.GET, "/members"), filters);
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
