package springSecurity.JWT.yummi.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


// form 로그인시 사용하는 필터이지만, 비활성화 시켰기 때문에 오버라이딩해서 해당 메소드를 작성해야 jwt 로그인 검증을 할 수 있다.
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
                    // 요청에서 username과 password를 추출한다.
                    // 기본으로 사용되는 것은 다음의 이름이고, 만약 필요한 필드가 email이라면 아래 방법으로 구현할 수 있다
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        // obtainPassword(request) 메소드는 request.getParameter("password"); 와 같다.
//        String email = request.getParameter("email");

        /*
       기본적으로 제공되는 메소드인 obtainUsername(request)과 obtainPassword(request)의 경우 multipart/form-data로 전송해야만 받을 수 있도록 설계가 되어 있다.
        따라서 application/json으로 받을 경우 받는 값은 직접 구현을 해야하고 application/json의 경우는 스트림 형태로 body에 받아야 하기 때문에 ObjectMapper()를 통해 받는 방법을 직접 구현해야 한다.
       */

        /* 해당 json 요청시 대응 방법
        {
          "username": "user",
          "password": "pass"
        }
        1. loginDTO 생성
        public class LoginDTO {

            private String username;
            private String password;
        }

        2. 스트림 형태로 값 받아오는 로직 추가 후 값을 추가시킨다.
        LoginDTO loginDTO = new LoginDTO();

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = request.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginDTO = objectMapper.readValue(messageBody, LoginDTO.class);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println(loginDTO.getUsername());

        String username = loginDTO.getUsername();
        String password = loginDTO.getPassword();
         */
        
        System.out.println("===============================================");
        System.out.println("username = " + username);
        System.out.println("password = " + password);
        System.out.println("===============================================");

        // spring security에서 username, password를 검증하기 위해서는 token에 담아야한다.
        /*
        UsernamePasswordAuthenticationToken은 2가지 값을 가진다

        식별자: 인증 과정에서 사용자의 고유 식별자로 사용된다. 일반적으로는 사용자가 입력한 아이디(username)가 이 값에 들어간다.
         오버라이딩된 로직으로 검증 할 수있다면 무슨 값을 넣어도 크게 상관 없다.
         기본적으로 UsernamePasswordAuthenticationToken에 사용되는 필드는 username과 password이지만,
         이를 변경하여 다른 식별자(예: email, userId 등)를 사용할 수 있다. username 대신 다른 필드를 사용하고 싶다면, override하여 처리할 수 있다.

        비밀번호 (password): 사용자가 입력한 비밀번호로, 인증을 수행할 때 이 값을 사용하여 해당 사용자에 대한 인증을 검증한다.
         
        */
                                                        // 해당 객체는 manager에게 전달해주기위한 dto 역할을 하는 객체이다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token 검증을 위해 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행하는 메소드 (JWT를 발급)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

    }

}
