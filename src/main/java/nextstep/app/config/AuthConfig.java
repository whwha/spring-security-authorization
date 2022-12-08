package nextstep.app.config;

import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationProvider;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.authorization.RoleManager;
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
    public FilterChainProxy filterChainProxy(
        SecurityFilterChain loginSecurityFilterChain,
        SecurityFilterChain membersSecurityFilterChain
    ) {
        return new FilterChainProxy(
            loginSecurityFilterChain,
            membersSecurityFilterChain
        );
    }

    @Bean
    public SecurityFilterChain loginSecurityFilterChain(
        AuthenticationManager authenticationManager,
        SecurityContextRepository securityContextRepository
    ) {
        return new DefaultSecurityFilterChain(
            new MvcRequestMatcher(
                HttpMethod.POST,
                "/login"
            ),
            new UsernamePasswordAuthenticationFilter(
                authenticationManager,
                securityContextRepository
            )
        );
    }

    @Bean
    public SecurityFilterChain membersSecurityFilterChain(
        AuthenticationManager authenticationManager,
        SecurityContextRepository securityContextRepository
    ) {
        return new DefaultSecurityFilterChain(
            new MvcRequestMatcher(
                HttpMethod.GET,
                "/members"
            ),
            new BasicAuthenticationFilter(
                authenticationManager,
                securityContextRepository
            ),
            new AuthorizationFilter(securityContextRepository, new RoleManager("ADMIN"))
        );
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
