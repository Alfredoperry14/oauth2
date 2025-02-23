package com.example.oauth2;

import java.util.Map;
import java.util.Collections;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.config.Customizer;

@EnableWebSecurity
@SpringBootApplication
@RestController
public class Oauth2Application {

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		if (principal == null) {
			return Collections.singletonMap("error", "User not authenticated");
		}
	
		// Try getting the name, fallback to GitHub username
		String name = principal.getAttribute("name");
		if (name == null || name.isEmpty()) {
			name = principal.getAttribute("login"); // Use GitHub username instead
		}
	
		return Collections.singletonMap("name", name);
	}

	public static void main(String[] args) {
		SpringApplication.run(Oauth2Application.class, args);
	}

@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/", "/oauth2/**", "/user").permitAll()
				.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers("/logout")) // Disable CSRF for logout
			.logout(logout -> logout
				.logoutUrl("/logout")
				.logoutSuccessHandler((request, response, authentication) -> {
					response.setStatus(HttpServletResponse.SC_OK);
				})
				.deleteCookies("JSESSIONID") // Clear cookies
				.invalidateHttpSession(true) // Invalidate session
			)
			.oauth2Login(Customizer.withDefaults());

		return http.build();
	}
}

