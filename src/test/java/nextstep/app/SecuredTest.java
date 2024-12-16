package nextstep.app;

import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecuredTest {
    private static final Member TEST_ADMIN_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;
    private static final Member TEST_USER_MEMBER = InmemoryMemberRepository.USER_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @DisplayName("ADMIN 권한을 가진 사용자가 요청할 경우 모든 회원 정보를 조회할 수 있다.")
    @Test
    void request_search_success_with_admin_user() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_ADMIN_MEMBER.getEmail() + ":" + TEST_ADMIN_MEMBER.getPassword()).getBytes());

        ResultActions response = mockMvc.perform(get("/search")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        ).andDo(print());

        response.andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.length()").value(2));
    }

    @DisplayName("일반 사용자가 요청할 경우 권한이 없어야 한다.")
    @Test
    void request_search_fail_with_general_user() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_USER_MEMBER.getEmail() + ":" + TEST_USER_MEMBER.getPassword()).getBytes());

        ResultActions response = mockMvc.perform(get("/search")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        ).andDo(print());

        response.andExpect(status().isForbidden());
    }
}
