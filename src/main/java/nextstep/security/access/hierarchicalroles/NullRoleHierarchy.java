package nextstep.security.access.hierarchicalroles;

import java.util.Collection;

public class NullRoleHierarchy implements RoleHierarchy {
    @Override
    public Collection<String> getReachableGrantedAuthorities(Collection<String> authorities) {
        return authorities;
    }
}
