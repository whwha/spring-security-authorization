package nextstep.security.authorization;

import nextstep.security.authentication.AuthenticationException;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class RoleHierarchy {
    private final String rule;


    public RoleHierarchy(String rule) {
        this.rule = rule;
    }

    public boolean check(String requestAuthority, String needAuthority) {
        List<String> rules = Arrays.stream(rule.split(">"))
                .map(String::trim)
                .collect(Collectors.toList());

        if (rules.contains(requestAuthority) && rules.contains(needAuthority)) {
            return rule.indexOf(requestAuthority) <= rule.indexOf(needAuthority);
        }
        throw new AuthenticationException();
    }
}
