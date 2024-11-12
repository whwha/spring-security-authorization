# spring-security-authorization

# 1단계 - 인가(권한 부여) 기능 구현
## 목표
- Request 요청별 권한 검증 로직과 메서드별 권한 검증 로직을 구현할 수 있다.

## 요구 사항
### 1. 사용자 권한 추가 및 검증
> ✅ `BasicAuthTest`와 `FormLoginTest`의 모든 테스트가 통과해야 한다.

- 다음의 기능을 수행하는 인터셉터를 추가한다.
    - `ADMIN` 권한을 가진 사용자만 `/members` 경로에 접근할 수 있도록 한다
    - `ADMIN` 권한이 없는 사용자는 접근하지 못하게 한다.

### 2. 메서드 애너테이션을 이용하여 접근 제어 기능을 적용
> ✅ `SecuredTest`의 모든 테스트가 통과해야 한다.

- `@Secured` 어노테이션을 사용하여 접근 권한을 설정하는 기능을 구현한다.
    - ADMIN 권한을 가진 사용자만 /search 경로에 접근할 수 있도록 한다
    - ADMIN 권한이 없는 사용자는 접근하지 못하게 한다. 
    - @Secured("ADMIN")와 같이 권한을 부여할 역할을 지정한다.

```java
@Secured("ADMIN")
@GetMapping("/search")
public ResponseEntity<List<Member>> search() {
    List<Member> members = memberRepository.findAll();
    return ResponseEntity.ok(members);
}
```

## 힌트
### 1. `CheckAuthenticationFilter` 참고
- `CheckAuthenticationFilter`는 요청한 사용자의 인가 여부를 판단하는 로직이 포함되어있다.
- 어드민 권한을 확인하는 필터를 새로 만들어도 좋고, 기존 필터를 활용해도 좋다.

### 2. 인증 객체에 권한을 가져오는 `getAuthorities()` 메서드가 추가
```java
public interface Authentication {
    Object getPrincipal();
    Object getCredentials();
    Set<String> getAuthorities();
    boolean isAuthenticated();
}
```

### 3. Spring AOP
- AOP 기능을 사용하기 위해 spring-boot-starter-aop 라이브러리를 추가해야 한다.
```groovy
implementation 'org.springframework.boot:spring-boot-starter-aop'
```

- `@EnableAspectJAutoProxy`설정을 넣어준다.
```java
@EnableAspectJAutoProxy
@Configuration
public class SecurityConfig {
    //...
```

- `@Secured` 샘플 코드
```java
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Secured {
    String value();
}
```

- `@Aspect` 애노테이션을 이용하여 메서드 실행 전후에 권한 검증 로직을 추가할 수 있다.
```java
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
```

- AOP를 구현하는 또 다른 방법으로 MethodInterceptor를 사용할 수 있다. 프록시를 생성하여 메서드 실행 전후에 권한 검증 로직을 넣을 수 있다.
```java
public class SecuredMethodInterceptor implements MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

    private final Pointcut pointcut;

    public SecuredMethodInterceptor() {
        this.pointcut = new AnnotationMatchingPointcut(null, Secured.class);
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Method method = invocation.getMethod();
        if (method.isAnnotationPresent(Secured.class)) {
            Secured secured = method.getAnnotation(Secured.class);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null) {
                throw new AuthenticationException();
            }
            if (!authentication.getAuthorities().contains(secured.value())) {
                throw new ForbiddenException();
            }
        }
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return pointcut;
    }

    @Override
    public Advice getAdvice() {
        return this;
    }

    @Override
    public boolean isPerInstance() {
        return true;
    }
}
```

- 참고 링크
  - https://www.baeldung.com/spring-aop-annotation


# 2단계 - 리펙터링

## 목표
- 권한 검증 과정을 추상화하여 구조화를 할 수 있다.
- 다양한 요청별 검증을 구현할 수 있다.

## 요구사항
### 1. GET /members/me 엔드포인트 구현 및 테스트 작성
자신의 인증 정보를 조회하는 새로운 엔드포인트를 구현한다. 이 때 기존에 구성했던 Form 로그인과 Basic 인증 방식을 모두 지원해야 한다. 그리고 이를 검증하는 테스트도 작성해야 한다.

- 인증된 사용자는 자신의 정보를 조회할 수 있는 **GET /members/me** 엔드포인트를 추가한다.
- **Form 로그인과 Basic 인증 방식 중 하나를 지원**한다.
- 인증된 사용자만 자신의 정보를 조회할 수 있다.
- `BasicAuthTest`나 `FormLoginTest`에 해당 기능을 검증하는 테스트를 작성한다.

```java
@DisplayName("인증된 사용자는 자신의 정보를 조회할 수 있다.")
@Test
void request_success_members_me() throws Exception {
    //...
}

@DisplayName("인증되지 않은 사용자는 자신의 정보를 조회할 수 없다.")
@Test
void request_fail_members_me() throws Exception {
    //...
}
```

### 2. 권한 검증 로직을 `AuthorizationFilter`로 리팩터링
시큐리티 필터 체인에서 요청별로 권한을 검증하는 로직은 하나의 필터에서 처리할 수 있도록 한다. 여러 인가 로직을 처리하는 하나의 필터 `AuthorizationFilter`를 구현한다.

- 기존에 여러 인터셉터로 나뉘어 있던 권한 부여(인가) 로직을 하나의 `AuthorizationFilter`로 통합한다.
- **GET /members** 경로는 `ADMIN` 권한을 가진 사용자만 접근 가능하도록 설정한다.
- **GET /members/me** 경로는 인증된 사용자라면 누구나 자신의 정보를 조회할 수 있도록 한다.
- **GET /search** 경로와 **/login**는 누구나 접근이 가능하도록 한다. (/search 요청은 @Secured로 권한 제어가 되므로 AuthorizationFilter에서는 누구나 접근이 가능하도록 설정한다)
- 그 외 경로는 아무도 접근할 수 없게 한다.

### (선택) 3. Role Hierarchy(권한의 계층 구조) 구현
#### 3.1 권한 계층 구조 설정
- ADMIN 역할을 가진 사용자도 USER 역할이 필요한 요청에 접근할 수 있도록 권한의 계층 구조를 구현한다.
- 설정 위치 및 방법은 자유롭게 구현한다. 예를 들면, 다음과 같이 설정하도록 할 수 있다.

```java
new RoleHierarchy("ADMIN > USER");
```

#### 3.2 권한의 계층 구조 테스트로 검증
- /members/me의 권한 설정을 USER로 수정한다.
- ADMIN 권한을 가진 사용자도 GET /members/me 경로에 접근할 수 있는지를 검증하는 테스트를 작성한다.

## 힌트
### 1. Role Hierarchy 구성 시
- Authority 검사 시 특정 문자열만 검사하는 것이 아니라 특정 문자열 하위 문자열도 함께 검사하도록 한다.
- 권한의 계층 구조를 활용하여 검증하는 책임을 가지는 객체를 작성하여 해결할 수 있다.

### 2. 테스트를 위한 초기 데이터 수정
- `InmemoryMemberRepository`의 초기값 중 USER_MEMBER의 역할을 다음과 같이 수정한다.
```java
Set.of() -> Set.of("USER"));
```

# 3단계 - 스프링 시큐리티 구조 적용
## 목표
- 스프링 시큐리티 구조를 이해하고 이와 유사항 형태로 리팩터링 할 수 있다.


## 요구사항
### 1. AuthorizationManager를 활용하여 인가 과정 추상화
스프링 시큐리티는 다양한 인가 방식을 처리할 수 있도록 AuthorizationManager 형태로 추상화해 놓았다. 기존에 구현한 다양한 인가 처리 로직을 추상화 하고 인가 방식에 따른 구현체를 구현한다.

- 인가 과정을 추상화한 `AuthorizationManager`를 작성한다. 이 때 필요한 `AuthorizationDecision`도 함께 작성한다. (실제 `AuthorizationManager`에는 verify도 있는데 이 부분에 대한 구현은 선택)
```java
@FunctionalInterface  
public interface AuthorizationManager<T> {  
    AuthorizationDecision check(Authentication authentication, T object);  
}
```

- SecuredMethodInterceptor와 Authorization Filter에서 작성된 인가 로직을 AuthorizationManager로 리팩터링 한다.
- 주요 클래스: `AuthorizationManager`, `RequestMatcherDelegatingAuthorizationManager`, `AuthorityAuthorizationManager`, `SecuredAuthorizationManager`

### 2. 요청별 권한 검증 정보를 별도의 객체로 분리하여 관리
요청별 권한 검증에 필요한 규칙은 security 패키지에 위치하는 것 보다 app 패키지 내에 위치하는게 자연스럽다. `RequestMatcherRegistry`와 `RequestMatcher`를 이용하여 요청별 권한을 설정하는 부분을 객체로 분리하고, 이 객체를 `SecurityConfig`에서 전달하기 수월한 구조로 만든다.

#### 참고사항
- 실제 `RequestMatcherDelegatingAuthorizationManager`에서 `RequestMatcherRegistry` 정보들을 가지는 변수의 타입이 `List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>>` 인데, 편의상 `RequestAuthorizationContext`부분은 제거하고 `List<RequestMatcherEntry<AuthorizationManager>>`로 하는 것을 추천한다.
- `RequestMatcherDelegatingAuthorizationManager`객체의 mappings 정보는 `AuthorizeHttpRequestsConfigurer`를 통해서 설정되는데 HttpSecurity를 비롯한 XXXConfigurer의 동작은 4일차에서 진행할 예정이므로 지금 단계에서는 무시하고 AuthorizationManager객체와 mappings을 생성하는 것에 집중한다.

```java
public class RequestMatcherEntry<T> {  
    private final RequestMatcher requestMatcher;  
    private final T entry;
```
```java
public interface RequestMatcher {
    boolean matches(HttpServletRequest request);
}
```

- `RequestMatcherRegistry`와 `RequestMatcher`를 작성하고, `RequestMatcher`의 구현체를 작성한다.
  - `AnyRequestMatcher`: 모든 경우 true를 리턴한다.
  - `MvcRequestMatcher`: method와 pattern(uri)가 같은지 비교하여 리턴한다. 
- `RequestMatcherEntry`의 T entry는 아래에 해당되는 각 요청별 인가 로직을 담당하는 `AuthorizationManager`가 된다. 예를 들어, 
  - /login은 모든 요청을 받을 수 있도록 `PermitAllAuthorizationManager`로 처리
  - /members/me는 인증된 사용자만에게만 권한을 부여하기 위해 `AuthenticatedAuthorizationManager`로 처리
  - /members는 "ADMIN" 사용자만에게만 권한을 부여하기 위해 `HasAuthorityAuthorizationManager`로 처리
  - 그 외 모든 요청은 권한을 제한하기 위해 `DenyAllAuthorizationManager`로 처리
- 주요 클래스: `RequestMatcherRegistry`, `RequestMatcherDelegatingAuthorizationManager`, `AuthorityAuthorizationManager`, `SecuredAuthorizationManager`, `AuthenticatedAuthorizationManager`

### (선택) 3. RoleHierarchy 리팩터링
RoleHierarchy는 기본적으로 NullRoleHierarchy가 설정된 다음 계층 구조의 권한 설정이 생길 경우 RoleHierarchyImpl가 동작하도록 되어있다. 실제 시큐리티의 구조를 참고해서 아래와 같이 설정하도록 수정한다.

> 실제 시큐리티 코드를 가져와서 구현한 뒤 불필요한 코드를 제거하는 방식으로 시도해도 좋다.

```java
@Bean
public RoleHierarchy roleHierarchy() {
    return RoleHierarchyImpl.with()
            .role("ADMIN").implies("USER")
            .build();
}
```

- RoleHierarchy를 설정하지 않았을 때 동작하도록 `NullRoleHierarchy`을 구현한다.
- 따라서, 설정하지 않았을 땐 기본적으로 `NullRoleHierarchy`가 동작하고, 설정할 경우에는 `RoleHierarchyImpl`가 동작하도록 한다.
  - `GrantedAuthority`의 구현은 선택, 필수는 아니다.
- 주요 클래스: `RoleHierarchy`, `RoleHierarchyImpl`, `NullRoleHierarchy`

## 힌트
### 1. AuthorizationManager 사용 예시
- `AuthorizationManager`는 특정 객체 T를 기준으로 사용자의 권한을 체크할 수 있는 추상화된 인터페이스이다.
- 인증 객체(Authentication)와 특정 리소스(T)를 이용해 인가 여부를 결정하는 로직을 구현할 수 있다.

```java
public class SecuredAuthorizationManager implements AuthorizationManager<MethodInterceptor> {
    @Override
    public AuthorizationDecision check(Authentication authentication, MethodInterceptor methodInterceptor) {
        if (authentication == null) {
            return new AuthorizationDecision(false);
        }
        // 권한 검증 로직 구현
        // ...
    }
}
```
- 요청에 따른 인가별 처리 시 요청(request) 정보가 필요하여 HttpServletRequest가 필요.
```java
public class RequestAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    @Override
    public AuthorizationDecision check(Authentication authentication, HttpServletRequest request) {
    //...
```

- 애너테이션을 활용한 인가 처리 시 메서드 정보가 필요하여 MethodInvocation를 활용.
```java
public class SecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Authentication authentication, MethodInvocation methodInvocation) {
    //...
```

### 2. Config 클래스에서 요청별 필요한 권한 설정 시 예시
- security 패키지가 아니라 이를 사용하는 app 패키지에서 요청별 권한 설정을 할 수 있도록 구성한다.
```java
@Bean
public RequestAuthorizationManager requestAuthorizationManager() {
    List<RequestMatcherEntry<AuthorizationManager>> mappings = new ArrayList<>();
    mappings.add(new RequestMatcherEntry<>(new MvcRequestMatcher(HttpMethod.GET, "/members/me"), new AuthenticatedAuthorizationManager()));
    mappings.add(new RequestMatcherEntry<>(new MvcRequestMatcher(HttpMethod.GET, "/members"), new AuthorityAuthorizationManager("ADMIN")));
    mappings.add(new RequestMatcherEntry<>(new MvcRequestMatcher(HttpMethod.GET, "/search"), new PermitAllAuthorizationManager()));
    mappings.add(new RequestMatcherEntry<>(new AnyRequestMatcher(), new PermitAllAuthorizationManager()));
    return new RequestAuthorizationManager(mappings);
}
```

### 3. @EnableMethodSecurity 동작 방식 및 SecuredMethodSecurityConfiguration import 확인 방법
- `@EnableMethodSecurity`에는 여러가지 상태가 있다.
```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(MethodSecuritySelector.class)
public @interface EnableMethodSecurity {
    boolean prePostEnabled() default true;
    boolean securedEnabled() default false;
    //...
}
```
- `MethodSecuritySelector`로 진입하여 `securedEnabled`를 검색하면 `SecuredMethodSecurityConfiguration`가 import되는 것을 확인할 수 있다.
```java
final class MethodSecuritySelector implements ImportSelector {
    public String[] selectImports(@NonNull AnnotationMetadata importMetadata) {
        if (!importMetadata.hasAnnotation(EnableMethodSecurity.class.getName()) && !importMetadata.hasMetaAnnotation(EnableMethodSecurity.class.getName())) {
            return new String[0];
        } else {
            //...
            if (annotation.securedEnabled()) {
                imports.add(SecuredMethodSecurityConfiguration.class.getName());
            }
            //...
```

### 4. AuthoritiesAuthorizationManager에서의 RoleHierarchy 활용
- 스프링 시큐리티에서는 Authentication의 권한이 어떤 권한까지 접근 가능한 지를 확인하는 방법으로 RoleHierarchy를 활용한다.
- 구현이 복잡한 경우 코드 그대로를 가져와서 단순화 시키면서 이해한 후 필요한 코드만 추려서 사용하면 조금 더 수월하게 적용할 수 있다.

```java
@Override
public AuthorityAuthorizationDecision check(Supplier<Authentication> authentication,
        Collection<String> authorities) {
    boolean granted = isGranted(authentication.get(), authorities);
    return new AuthorityAuthorizationDecision(granted, AuthorityUtils.createAuthorityList(authorities));
}

private boolean isGranted(Authentication authentication, Collection<String> authorities) {
    return authentication != null && isAuthorized(authentication, authorities);
}

private boolean isAuthorized(Authentication authentication, Collection<String> authorities) {
    for (GrantedAuthority grantedAuthority : getGrantedAuthorities(authentication)) {
        if (authorities.contains(grantedAuthority.getAuthority())) {
            return true;
        }
    }
    return false;
}

private Collection<? extends GrantedAuthority> getGrantedAuthorities(Authentication authentication) {
    return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
}
```


















