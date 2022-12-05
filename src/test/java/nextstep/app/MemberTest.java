package nextstep.app;

import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
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
    private static final Member TEST_MEMBER = InmemoryMemberRepository.TEST_MEMBER_1;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void request_with_basic_success() throws Exception {
        ResultActions loginResponse = requestWithBasicAuth(TEST_MEMBER.getEmail(), TEST_MEMBER.getPassword());

        loginResponse.andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.length()").value(2));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    void login_fail_with_no_user() throws Exception {
        ResultActions response = requestWithBasicAuth("none", "none");

        response.andExpect(status().isUnauthorized());
    }

    @Test
    void login_fail_with_invalid_password() throws Exception {
        ResultActions response = requestWithBasicAuth(TEST_MEMBER.getEmail(), "invalid");

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
