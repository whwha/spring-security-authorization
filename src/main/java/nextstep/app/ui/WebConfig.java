package nextstep.app.ui;

import nextstep.security.authentication.BasicAuthenticationInterceptor;
import nextstep.security.authorization.CheckAuthenticationInterceptor;
import nextstep.security.authentication.FormLoginAuthenticationInterceptor;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.DaoAuthenticationProvider;
import nextstep.security.authentication.ProviderManager;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContextHolderInterceptor;
import nextstep.security.userdetils.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Collections;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final UserDetailsService userDetailsService;

    public WebConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SecurityContextHolderInterceptor(securityContextRepository()));
        registry.addInterceptor(new BasicAuthenticationInterceptor(authenticationManager()));
        registry.addInterceptor(new FormLoginAuthenticationInterceptor(authenticationManager(), securityContextRepository())).addPathPatterns("/login");
        registry.addInterceptor(new CheckAuthenticationInterceptor()).addPathPatterns("/members");
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(daoAuthenticationProvider()));
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        return new DaoAuthenticationProvider(userDetailsService);
    }

    @Bean
    public HttpSessionSecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }
}
