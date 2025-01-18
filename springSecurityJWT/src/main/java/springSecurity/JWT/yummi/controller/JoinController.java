package springSecurity.JWT.yummi.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import springSecurity.JWT.yummi.dto.JoinDto;
import springSecurity.JWT.yummi.service.JoinService;

@Controller
@RequiredArgsConstructor
@ResponseBody
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDto joinDto){

        // curl을 통한 post 요청
        // curl -i -X POST -H "Content-Type: application/json" -d "{\"username\":\"user\",\"password\":\"pass\"}" http://localhost:8080/join
        System.out.println("joinDto = " + joinDto);
        joinService.joinProcess(joinDto);
        return "ok";
    }

}
