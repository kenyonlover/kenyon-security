package top.kenyon.kenyonsecurity.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import top.kenyon.kenyonsecurity.entity.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Spring Security默认的登录请求是一个 POST 请求，登录数据格式就是 key/value 的形式
 * 重写一个Filter集成Spring Security的登录用户密码处理类，重写验证逻辑
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    SessionRegistry sessionRegistry;

    /**
     * 重写登录逻辑
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        String verify_code = (String) request.getSession().getAttribute("captcha_code");
        if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE) || request.getContentType().equals(MediaType.APPLICATION_JSON_UTF8_VALUE)) {
            Map<String, String> loginData = new HashMap<>();
            try {
                loginData = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            } catch (IOException ignored) {
            }finally {
                String code = loginData.get("verify_code");
                checkCode(response, code, verify_code);
            }
            String username = loginData.get(getUsernameParameter());
            String password = loginData.get(getPasswordParameter());
            if (username == null) {
                username = "";
            }
            if (password == null) {
                password = "";
            }
            username = username.trim();
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    username, password);
            setDetails(request, authRequest);

            User user = new User();
            user.setUsername(username);
            sessionRegistry.registerNewSession(request.getSession(true).getId(), user);

            return this.getAuthenticationManager().authenticate(authRequest);
        } else {
            checkCode(response, request.getParameter("verify_code"), verify_code);
            return super.attemptAuthentication(request, response);
        }

    }

    /**
     * 校验验证码
     * @param response
     * @param code 用户输入验证码
     * @param verify_code session中下发过的验证码
     */
    public void checkCode(HttpServletResponse response, String code, String verify_code) {
        if (code == null || verify_code == null || "".equals(code) || !verify_code.toLowerCase().equals(code.toLowerCase())) {
            //验证码不正确
            throw new AuthenticationServiceException("验证码不正确");
        }
    }
}
