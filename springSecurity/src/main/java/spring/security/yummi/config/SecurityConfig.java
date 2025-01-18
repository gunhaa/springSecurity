package spring.security.yummi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 해당 메소드를 bean으로 만들어놓으면 hash 방식의 단방향 암호화를 할 수 있다.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        // 권한이 필요한 페이지를 설정할 수 있다.
        // 람다를 인자로 받는다
        // config클래스는 security 버전에 따라 많이 다르다. 버전이 다르다면 찾아봐야함
        // https://www.youtube.com/watch?v=NdRVhOccuOs&list=PLJkjrxxiBSFCKD9TRKDYn7IE96K2u3C3U&index=4
        http.authorizeHttpRequests((auth) -> auth
                             // path를 넣는다 ,         모든 사용자 접근 가능 등 다양한 메소드 존재
                        .requestMatchers("/", "/login", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        //hierarchy 방식으로도 구현할 수 있다
                        // https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html
                        // security 스펙 static으로 변경
                        // https://github.com/spring-projects/spring-security/blob/main/core/src/main/java/org/springframework/security/access/hierarchicalroles/RoleHierarchyImpl.java

                        // **로 wildcard를 사용할 수 있다.
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        // 처리하지 않는 나머지 경로 처리
                        // 권한 있는 사람들만 사용 가능
                        .anyRequest().authenticated()
                );


        // Spring Security의 두가지 로그인 방식 - form / httpBasic

        // form 로그인 방식
        // 로그인 페이지가 필요한 경우 리다이렉션 시킴
        http.formLogin((auth) -> auth.loginPage("/login")
                // 로그인시 보낼 주소 설정
                /*
                loginProcessingUrl 설정의 이유(잘 이해가 안됨)
                스프링 시큐리티는 로그인 처리를 위한 URL을 자동으로 처리하는 기능을 제공한다.
                loginProcessingUrl은 서버 측에서 로그인 처리를 수행할 경로를 설정하는 것이다.
                즉, 로그인 폼에서 사용자가 제출하는 로그인 요청이 어느 URL로 전송될지를 설정하는 것이다.
                */
                .loginProcessingUrl("/loginProc")
                .permitAll()
        );

        // httpBasic 로그인 방식
        // Http Basic 인증 방식은 아이디와 비밀번호를 Base64 방식으로 인코딩한 뒤 HTTP 인증 헤더에 부착하여 서버측으로 요청을 보내는 방식이다.
//        http.httpBasic(Customizer.withDefaults());


        // CSRF(Cross-Site Request Forgery)는 요청을 위조하여 사용자가 원하지 않아도 서버측으로 특정 요청을 강제로 보내는 방식이다.
        // (회원 정보 변경, 게시글 CRUD를 사용자 모르게 요청)
        // 스프링에는 csrf토큰이 활성화되있어서 개발환경에서는 우선 disable시켜야한다.
        //http.csrf((auth)-> auth.disable());
        // 해당 설정이 없다면 enable로 진행되고, spring security 필터에서 요청(POST, PUT, DELETE)에 대해서 토큰 검증을 진행하기 때문에 특별한 로직이 필요하다
        // 요청할때 ajax, form 요청 등에서 모두 토큰을 넣어서 요청을 보내야 요청이 통과된다.
        // 해당 방법 예시
        /* POST 요청시
        <form action="/loginReceiver" method="post" name="loginForm">
            <input type="text" name="username" placeholder="아이디"/>
            <input type="password" name="password" placeholder="비밀번호"/>
            <input type="hidden" name="_csrf" value="{{_csrf.token}}"/>
            <input type="submit" value="로그인"/>
        </form>
        */

        /* ajax 요청시
        HTML <head> 구획에 아래 요소 추가
        <meta name="_csrf" content="{{_csrf.token}}"/>
        <meta name="_csrf_header" content="{{_csrf.headerName}}"/>
        */

        // sesiion 설정 방법
        http.sessionManagement((auth)-> auth
                // 최대 로그인 가능 허용 갯수
                .maximumSessions(1)
                // boolean값을 넣어주어 로그인 개수를 초과 했을때의 행동을 설정 할 수 있다
                // true : 초과시 새로운 로그인 차단
                // false : 초과시 기존 세션 하나 삭제
                .maxSessionsPreventsLogin(true)
        );

        // hacker의 세션 고정 공격을 보호하기 위한 방법

        /*
        # 세션 고정 공격방법
        해커가 세션 고정(Session Fixation) 공격을 수행할 때, 유저를 특정 세션 ID로 유도하는 것이 핵심이다. 이를 위해 해커는 다음과 같은 방법을 사용한다

        ## 1. 세션 ID 생성 및 확보
        해커가 서버에서 세션 ID를 미리 생성한다.

        해커는 의도적으로 웹사이트에 접속해 유효한 세션 ID를 얻는다.
        예를 들어, JSESSIONID=ABC123라는 세션 ID를 확보한다.

        일부 웹 서버는 클라이언트가 임의로 생성한 세션 ID를 허용할 수 있다.
        해커는 자신이 원하는 세션 ID를 서버에 전달해 강제로 사용되도록 할 수도 있다.

        ## 2. 유저를 특정 세션 ID로 유도
        해커가 확보한 세션 ID를 유저에게 사용하도록 만드는 단계는 다음과 같다

        - 악성 링크 유도
        해커는 다음과 같은 URL을 생성해서 링크를 이메일, 피싱 사이트, 악성 광고 등으로 유저에게 전달한다.

        `https://example.com/login?JSESSIONID=ABC123`

        유저가 이 링크를 클릭하면, 브라우저는 해당 세션 ID(ABC123)를 서버로 전달한다.

        - 쿠키 조작
        일부 경우, 해커는 XSS(Cross-Site Scripting) 공격을 통해 클라이언트의 브라우저에서 세션 쿠키를 강제로 설정할 수 있다.

        `document.cookie = "JSESSIONID=ABC123";`

        ## 3. 유저가 세션 ID를 사용
        유저는 공격자가 설정한 세션 ID(ABC123)로 서버에 요청을 보내게 된다.
        서버는 해당 세션 ID를 유효하다고 간주하고, 로그인 후에도 동일한 세션 ID를 유지한다(sessionFixation().none() 설정의 경우)
        .
        ## Role(역할)을 얻어오는 과정

        ### 1. 세션 ID와 유저 데이터의 매핑
        서버는 세션 ID를 통해 유저 데이터를 조회한다.

        유저가 로그인하면, 서버는 인증 정보를 기반으로 유저의 역할(Role)을 확인한다.
        이 역할 정보는 보통 데이터베이스 또는 다른 저장소에 저장되어 있다.
        `SELECT role FROM users WHERE username = 'exampleUser';`

        서버는 조회한 역할 정보를 세션에 저장한다.
        `session.setAttribute("userRole", "ADMIN");`

        이후 유저가 요청을 보낼 때, 서버는 세션 ID를 통해 유저 역할 정보를 가져온다.
        `String role = (String) session.getAttribute("userRole");`
        ### 2. 해커가 역할 정보를 사용하는 과정
        - 공격자가 세션 ID를 확보한 경우
        해커가 특정 세션 ID(ABC123)를 확보하고 유저가 해당 세션을 사용하게 유도하면, 이후 이 세션에 저장된 역할 정보도 해커가 사용할 수 있다.
        ABC123 세션에 userRole=ADMIN이 저장되어 있다면, 해커는 관리자 권한을 가진 상태로 서버에 접근할 수 있다.
        - 로그인 후 역할 정보 갱신
        만약 서버가 로그인 시 세션 ID를 갱신하지 않는 경우(`sessionFixation().none()`), 해커가 미리 확보한 세션 ID에 유저의 역할 정보가 갱신된다.
        해커는 자신이 얻은 세션 ID를 계속 사용해 유저의 역할로 서버를 조작할 수 있다.

        */
        http.sessionManagement((auth)-> auth
                // 로그인 시 세션 정보 변경 안함
                //.sessionFixation().none()
                // 로그인 시 세션 새로 생성
                .sessionFixation().newSession()
                // 로그인 시 동일한 세션에 대한 id 변경(주로 이 방법을 사용한다.)
                //.sessionFixation().changeSessionId()
        );

        return http.build();
    }
}
