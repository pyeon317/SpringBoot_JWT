package com.team04.jwt.Controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.team04.jwt.command.UserVO;
import com.team04.jwt.security.config.JWTService;

@RestController//rest
public class APIController {

//	//로그인 기능 가정
//	@PostMapping("/login")
//	public ResponseEntity<String> login(@RequestBody UserVO vo) {
//		
//		//로그인 시도 > 성공이라고 가정
//		System.out.println(vo.toString());
//		
//		String token = JWTService.createToken(vo.getUsername());
//		
//		return new ResponseEntity<>(token, HttpStatus.OK);
//	}
////	
//	//사용자정보 확인
//	//토큰을 헤더에 담아서 사용자 정보와 함께 요청
//	@PostMapping("/api/v1/getInfo")
//	public ResponseEntity<Object> getInfo(HttpServletRequest request){
//		
//		//헤더에 담긴 토큰
//		String token = request.getHeader("Autorization");
//		
//		//토큰의 무결성 검사
//		try {
//			boolean result = JWTService.validateToken(token);
//			System.out.println("토큰무결성:"+result);
//			
//		} catch (Exception e) {
//			e.printStackTrace();
//			return new ResponseEntity<>("토큰위조",HttpStatus.UNAUTHORIZED);
//		}
//		
//		
//		
//		return new ResponseEntity<>("success get info~", HttpStatus.OK);
//	}
	
	
	//
	//시큐리티 요청테스트
	@GetMapping("/api/v1/hello")
	public String hello() {
		return "<h3>헬로</h3>";
	}
		
		
	
	
}
