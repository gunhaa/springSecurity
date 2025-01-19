package springSecurity.JWT.yummi.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import springSecurity.JWT.yummi.dto.CustomUserDetails;
import springSecurity.JWT.yummi.entity.UserEntity;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 Authorization 헤더를 찾는다
        String authorization = request.getHeader("Authorization");

        if(authorization == null || !authorization.startsWith("Bearer ")){
            // Authorization 헤더를 검증한다.
            System.out.println("token null");
            // 필터체인의 dofilter를 통해서 현 filter를 종료하고 chain의 다음 filter로 값들을 넘겨준다.
            filterChain.doFilter(request, response);
            // 조건이 해당되면 메소드 종료(필수)
            return;
        }
        //Bearer 부분 제거 후 토큰 획득
        String token = authorization.split(" ")[1];
        // 토큰 소멸시간 검증
        if(jwtUtil.isExpired(token)){
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            // 조건이 해당되면 메소드 종료(필수)
            return;
        }
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userEntity를 생성하여 값 세팅
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        // 검증 필요없으므로 임시 비밀번호 생성
        userEntity.setPassword("tempPassword");
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        /* 위에서 확인을 했지만 인증 토큰을 생성하는 이유
        JWT 토큰을 통해 사용자가 인증된 상태이지만, 스프링 시큐리티의 인증 시스템에 인증된 사용자 정보를 SecurityContext에 등록해야 한다.
         그래야 스프링 시큐리티가 인증된 사용자로 요청을 처리할 수 있다.
        */
        // loginFilter가 UsernamePasswordAuthenticationFilter를 상속받았다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다음 필터 체인으로
        filterChain.doFilter(request, response);
    }

}
