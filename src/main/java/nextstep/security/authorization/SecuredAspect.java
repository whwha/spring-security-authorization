package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.context.SecurityContextHolder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Method;

@Aspect
public class SecuredAspect {

    @Before("@annotation(nextstep.security.authorization.Secured)")
    public void checkSecured(JoinPoint joinPoint) throws NoSuchMethodException {
        Method method = getMethodFromJoinPoint(joinPoint);
        String secured = method.getAnnotation(Secured.class).value();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AuthenticationException();
        }
        if (!authentication.getAuthorities().contains(secured)) {
            throw new ForbiddenException();
        }
    }

    private Method getMethodFromJoinPoint(JoinPoint joinPoint) throws NoSuchMethodException {
        Class<?> targetClass = joinPoint.getTarget().getClass();
        String methodName = joinPoint.getSignature().getName();
        Class<?>[] parameterTypes = ((MethodSignature) joinPoint.getSignature()).getParameterTypes();

        return targetClass.getMethod(methodName, parameterTypes);
    }
}
