package spring.security.yummi.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;
import java.util.Iterator;

@Controller
@RequiredArgsConstructor
public class MainController {


    @GetMapping("/")
    public String mainP(Model model){

        String id = SecurityContextHolder.getContext().getAuthentication().getName();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        System.out.println("id = " + id);
        System.out.println("role = " + role);


        // 비 로그인시
        // id = anonymousUser
        // role = ROLE_ANONYMOUS
        // 로그인시 입력해놓은 값 출력
        // id = user1
        // role = ROLE_ADMIN

        // 값을 체크해서 role이 없으면 막는 방식으로 응용하면 된다.

        model.addAttribute("id", id);
        model.addAttribute("role", role);


        // spring security가 활성화 중이라 페이지가 없어도 로그인화면이 보인다
        // spring security가 필터를 통해 요청을 가로채서 인가를 요청하는 것이다.
        // 인가 작업 커스텀에는 spring security Config를 이용해서 할 수 있다.
        // id user, pw console에 적용된 것으로 로그인이 가능하다
        return "main";
    }

}
