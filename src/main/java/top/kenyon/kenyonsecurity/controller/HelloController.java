package top.kenyon.kenyonsecurity.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.CircleCaptcha;
import cn.hutool.captcha.ShearCaptcha;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/welcome")
    public String welcome(){
        return "welcome kenyon-security!";
    }

    @GetMapping("/admin/hello")
    public String admin(){
        return "admin";
    }

    @GetMapping("/user/hello")
    public String user(){
        return "user";
    }

    @GetMapping("getUserDetails")
    public Object getUserDetails(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        return details;
    }

    @GetMapping("/verifyCode")
    public void verifyCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //定义图形验证码的长、宽、验证码字符数、干扰线宽度
//        ShearCaptcha captcha = CaptchaUtil.createShearCaptcha(200, 100, 4, 4);
        //定义图形验证码的长、宽、验证码字符数、干扰元素个数
        CircleCaptcha captcha = CaptchaUtil.createCircleCaptcha(200, 100, 4, 20);
        String code = captcha.getCode();
        HttpSession session = request.getSession();
        session.setAttribute("captcha_code", code);
        ServletOutputStream outputStream = null;
        try {
            outputStream = response.getOutputStream();
            captcha.write(outputStream);
        } finally {
            outputStream.close();
        }

    }
}
