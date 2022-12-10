package nextstep.app;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.Role;
import nextstep.security.context.SecurityContextHolder;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InMemoryMemberRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class MemberTest {
    private static final Member TEST_ADMIN_MEMBER = InMemoryMemberRepository.ADMIN_MEMBER;
    private static final Member TEST_USER_MEMBER = InMemoryMemberRepository.USER_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void request_success_with_admin_user() throws Exception {
        ResultActions response = requestWithBasicAuth(TEST_ADMIN_MEMBER.getEmail(), TEST_ADMIN_MEMBER.getPassword());

        response.andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.length()").value(2));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getAuthorities()).contains(Role.ADMIN.name());
    }

    @Test
    void request_fail_with_general_user() throws Exception {
        ResultActions response = requestWithBasicAuth(TEST_USER_MEMBER.getEmail(), TEST_USER_MEMBER.getPassword());

        response.andExpect(status().isForbidden());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getAuthorities()).isEmpty();
    }

    @Test
    void request_fail_with_no_user() throws Exception {
        ResultActions response = requestWithBasicAuth("none", "none");

        response.andExpect(status().isUnauthorized());
    }

    @Test
    void request_fail_invalid_password() throws Exception {
        ResultActions response = requestWithBasicAuth(TEST_ADMIN_MEMBER.getEmail(), "invalid");

        response.andExpect(status().isUnauthorized());
    }

    private ResultActions requestWithBasicAuth(String username, String password) throws Exception {
        String token = Base64.getEncoder().encodeToString((username + ":" + password).getBytes());

        return mockMvc.perform(get("/members")
                        .header("Authorization", "Basic " + token)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );
    }
}
