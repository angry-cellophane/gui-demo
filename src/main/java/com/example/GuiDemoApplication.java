package com.example;

import com.example.web.filters.CsrfHeaderFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
@RestController
public class GuiDemoApplication {

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
              .httpBasic()
            .and()
              .authorizeRequests()
                .antMatchers("/index.html", "/home.html", "/login.html", "/").permitAll()
                .anyRequest().authenticated()

            .and()
              .addFilterAfter(new CsrfHeaderFilter(), CsrfFilter.class)
              .csrf().csrfTokenRepository(csrfTokenRepository())
            .and()
              .logout().logoutSuccessUrl("/").clearAuthentication(true).deleteCookies("XSRF-TOKEN", "JSESSIONID");
        }

        private CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
            repository.setHeaderName("X-XSRF-TOKEN");
            return repository;
        }
    }

    @RequestMapping("/user")
    public Map<String, Object> user(Principal user) {
        Map<String, Object> model = new HashMap<>();
        model.put("name", user.getName());
        return model;
    }

    @RequestMapping("resource")
    public Map<String, Object> resource() {
        Map<String, Object> model = new HashMap<>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "Hello world!");
        return model;
    }

	public static void main(String[] args) {
		SpringApplication.run(GuiDemoApplication.class, args);
	}
}
