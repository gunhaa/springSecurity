package spring.security.yummi.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import spring.security.yummi.dto.JoinDto;
import spring.security.yummi.service.JoinService;

@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String joinP(){
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(JoinDto joinDto){

        System.out.println("joinDto = " + joinDto);

        joinService.joinProcess(joinDto);

        return "redirect:/login";
    }

}
