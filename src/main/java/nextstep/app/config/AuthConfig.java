package nextstep.app.config;

import nextstep.security.access.matcher.AnyRequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationProvider;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.userdetails.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
        return new FilterChainProxy(List.of(securityFilterChain()));
    }

    @Bean
    public SecurityFilterChain securityFilterChain() {
        List<Filter> filters = new ArrayList<>();
        filters.add(new UsernamePasswordAuthenticationFilter(authenticationManager(), securityContextRepository()));
        filters.add(new BasicAuthenticationFilter(authenticationManager()));
        return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, filters);
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
