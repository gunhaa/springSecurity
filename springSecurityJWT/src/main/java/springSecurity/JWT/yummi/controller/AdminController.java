package springSecurity.JWT.yummi.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@ResponseBody
public class AdminController {


    @GetMapping("/admin")
    public String adminP(){
        return "adminController";
    }

}
