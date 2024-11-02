package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;

import java.lang.reflect.Method;

public class SecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Authentication authentication, MethodInvocation methodInvocation) {
        String authorities = getAuthorities(methodInvocation);

        if (authentication == null) {
            return new AuthorizationDecision(false);
        }

        boolean hasRequiredRole = authentication.getAuthorities().stream()
                .anyMatch(role -> role.equals(authorities));

        if (!hasRequiredRole) {
            return new AuthorizationDecision(false);
        }

        return new AuthorizationDecision(true);
    }

    private String getAuthorities(MethodInvocation methodInvocation) {
        Method method = methodInvocation.getMethod();
        Object target = methodInvocation.getThis();
        Class<?> targetClass = (target != null) ? target.getClass() : null;

        return resolveAuthorities(method, targetClass);
    }

    private String resolveAuthorities(Method method, Class<?> targetClass) {
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
        Secured secured = specificMethod.getAnnotation(Secured.class);
        return (secured != null) ? secured.value() : null;
    }
}
