package com.team04.jwt.security.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.team04.jwt.security.filter.CustomLoginFilter;
import com.team04.jwt.security.filter.FilterOne;
import com.team04.jwt.security.filter.FilterTwo;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	//비밀번호 암호화객체
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		
		
		
		//1.기본로그인 방식, 세션, 베이직인증, csrf초큰 전부 사용하지 x
		http.csrf().disable();
		
		http.formLogin().disable();//form기반 로그인을 사용하지 x
		http.httpBasic().disable();//authorization: 아이디 형식으로 넘어오는 basic인증을 사용하지 x
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//세션 인증 기반을 사용하지 않고, JWT사용해서 인증
		
		http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()); //모든 요청은 전부 허용
		
		//1. 크로스오리진 필터 생성 cors
		http.cors( Customizer.withDefaults() );
		
		//2.필터체이닝 연습
		//http.addFilter(new FilterOne());//시큐리티 타입의 필터를 등록할 때
		//http.addFilterBefore(new FilterOne(), UsernamePasswordAuthenticationFilter.class);
		//http.addFilterBefore(new FilterTwo(), FilterOne.class); //filterone보다 먼저
		//http.addFilterAfter(new FilterTwo(), FilterOne.class); //filterone보다 이후
		
		
		//3.로그인 시도에 AuthenticationManager가 필요합니다.
		//++UserDetailService객체 and PasswordEncoder가 반드시 필요
		AuthenticationManager authenticationManager = 
				authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
		
		System.out.println(authenticationManager);
		
		//4.로그인필터를 등록
		http.addFilter( new CustomLoginFilter(authenticationManager) );
		
		
		
		return http.build();
	}
	
	//로그인 시도에 필요한 AuthenticationManager 객체
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
	
	
	
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*")); //모든 요청주소를 허용함
		configuration.setAllowedMethods(Arrays.asList("*")); //모든 요청 메서드를 허용함
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration); //모든 요창에 대해서
		return source;
	}
	
}
