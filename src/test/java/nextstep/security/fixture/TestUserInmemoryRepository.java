package nextstep.security.fixture;

import nextstep.security.userdetails.BaseUser;

import java.util.*;
import java.util.stream.Collectors;

public class TestUserInmemoryRepository {
    public static final BaseUser TEST_MEMBER_1 = new BaseUser("a@a.com", "password", Set.of("ADMIN"));
    public static final BaseUser TEST_MEMBER_2 = new BaseUser("b@b.com", "password", Set.of("ADMIN"));
    private static final Map<String, BaseUser> users = new HashMap<>();

    static {
        users.put(TEST_MEMBER_1.getUsername(), TEST_MEMBER_1);
        users.put(TEST_MEMBER_2.getUsername(), TEST_MEMBER_2);
    }

    public Optional<BaseUser> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public List<BaseUser> findAll() {
        return users.values().stream().collect(Collectors.toUnmodifiableList());
    }
}
