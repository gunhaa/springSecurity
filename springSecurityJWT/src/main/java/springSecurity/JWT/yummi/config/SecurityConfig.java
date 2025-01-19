package springSecurity.JWT.yummi.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import springSecurity.JWT.yummi.jwt.JWTFilter;
import springSecurity.JWT.yummi.jwt.JWTUtil;
import springSecurity.JWT.yummi.jwt.LoginFilter;

import java.util.Collections;

@Configuration
// springSecurity 설정임을 알림
@EnableWebSecurity
public class SecurityConfig {

    // 버전별로 설정 방법이 다르니 알아두어야한다
    // 해당 방법은 6.xx version의 설정 방법

    // 비밀번호를 hash로 암호화시키기 위해서
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    /*
     Spring이 AuthenticationConfiguration 객체를 자동으로 생성하여 SecurityConfig 클래스의 생성자로 주입한다.
    이 과정은 Spring 컨테이너의 의존성 주입에 의해 이루어진다.
    AuthenticationConfiguration은 Spring Security에서 제공하는 클래스이며, 기본적으로 Spring Context에 의해 관리되는 Bean이다.
    */
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 설정에 대한 세부 설명은 springSecurity의 SecurityConfig에 있다.

        // csrf disable
        // session이 stateless해서 보안을 강화하지 않아도 괜찮다.
        http.csrf((auth)->auth.disable());

        //Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 인증 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) ->
                auth.requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // 다른 요청들에 대해서는, 로그인한 사용자만 접근 할 수 있게한다.
                        .anyRequest().authenticated());

        // 세션 설정
        // 가장 중요하다, 세션 STATELESS 설정이 필수
        http.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 필터 등록
        // UsernamePasswordAuthenticationFilter를 LoginFilter로 대체하는 설정
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 필터 등록
        // JWTFilter를 추가해야 JWT를 통한 인증이 가능하다
        // loginfilter앞에 추가한다.
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // cors설정은 2가지를 해줘야한다(security config ->토큰 발행 / WebMvcConfigurer 구현 -> 컨트롤러요청 처리)
        http.cors((corsCustomizer) -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                CorsConfiguration configuration = new CorsConfiguration();

                // 허용할 Origin(출처) 설정 - 예를 들어, 프론트 서버가 http://localhost:3000에서 실행되고 있다면
                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                // 허용할 메소드(모두, GET/POST/PUT/DELETE)
                configuration.setAllowedMethods(Collections.singletonList("*"));
                // 클라이언트가 credentials(쿠키 등)을 포함하여 요청할 수 있게 허용하는 설정
                // 'true'로 설정하면, 클라이언트는 자격 증명(credentials)을 서버로 보낼 수 있게 된다.
                // 예를 들어, 로그인한 상태에서 요청을 보내려면 이 설정이 필요하다.
                configuration.setAllowCredentials(true);
                // 헤더(모든)
                // 클라이언트가 보내는 요청 헤더를 제한하는 데 사용된다.
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                //  preflight 요청의 캐시 시간을 설정한다.
                // Preflight 요청이란, 브라우저가 CORS 요청을 보내기 전에 서버에 먼저 확인하는 예비 요청이다.
                // 브라우저는 보안을 위해 다른 도메인으로의 요청을 보내기 전에 서버의 응답을 확인하기 때문이다.
                // 브라우저는 CORS(Cross-Origin Resource Sharing) 정책에 따라,
                // 실제 요청을 보내기 전에 미리 서버에 "preflight 요청"을 보낼 수 있다.
                //  이 요청은 주로 "옵션 요청(OPTIONS)"이라고 부르며, 실제 데이터를 보내기 전에 서버가 그 요청을 허용하는지 확인하는 과정이다.
                //Preflight 요청 (OPTIONS 요청)
                //Preflight 요청은 브라우저가 실제 요청을 보내기 전에 서버에 보내는 사전 요청이다.
                // 이 요청은 주로 CORS 정책에 따라, 어떤 HTTP 메소드(예: POST, PUT, DELETE)나 어떤 요청 헤더를 사용할 것인지에 대해 서버의 허용 여부를 묻는 요청이다.
                // setMaxAge(3600L)는 이 preflight 요청의 결과를 캐시하는 시간을 설정한다.
                // 즉, 서버가 1시간 동안 동일한 CORS 요청에 대해 preflight 요청을 반복하지 않도록 한다.
                // *** PREFLIGHT는 모든 요청에 보내지나? ***
                // X, Preflight 요청이 발생하는 조건은 다음과 같다.
                //특정 HTTP 메소드를 사용할 때: 기본적으로 GET, HEAD, POST와 같은 간단한 요청은 preflight 요청을 보내지 않는다.
                //그러나 PUT, DELETE, PATCH 같은 HTTP 메소드를 사용할 때는 preflight 요청이 발생할 수 있다.
                //특히 CORS 정책에 따라 이러한 요청을 보내기 전에 브라우저가 서버가 이를 허용하는지 확인하기 위해 OPTIONS 요청을 보낸다.
                //비표준 HTTP 헤더를 포함할 때: 기본적인 요청 헤더(Content-Type: application/x-www-form-urlencoded, Content-Type: multipart/form-data, Content-Type: text/plain)는 preflight 요청을 트리거하지 않지만, 비표준 헤더를 추가하면 preflight 요청이 발생한다.
                // 예를 들어, Authorization, X-Custom-Header, X-Request-ID와 같은 비표준 헤더가 포함될 경우에 해당한다.
                //CORS 정책을 준수해야 하는 경우: 다른 도메인(cross-origin)으로 요청을 보내는 경우, 브라우저는 CORS 정책을 따르기 위해 preflight 요청을 보낼 수 있다.
                // 하지만 CORS 정책에서 "간단한 요청(simple requests)"에 해당하는 경우에는 preflight 요청이 발생하지 않는다.
                configuration.setMaxAge(3600L);
                //CORS 요청을 보내면, 서버에서 응답이 오고, 브라우저는 그 응답에서 특정 헤더를 볼 수 있어야 할 때가 있다.
                //setExposedHeaders는 클라이언트(브라우저)가 서버 응답에 포함된 특정 헤더를 읽을 수 있도록 허용하는 설정이다.
                // 해당 설정이없다면 클라이언트는 헤더에 접근을 못하는 상태가 된다.
                // "접근을 못하는 상태"는 암호화가 되어 있다는 의미가 아니라,
                // CORS 정책에 의해 브라우저가 특정 헤더를 클라이언트에서 읽을 수 없다는 의미한다.(자바스크립트에서 해당 헤더에 접근할 수 없다는 의미)
                // 주로 인증 토큰을 담고 있는 헤더이기 때문에, 클라이언트가 이 값을 읽을 수 있도록 하는 것이다.
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                return configuration;
            }
        }));

        return http.build();
    }

}
