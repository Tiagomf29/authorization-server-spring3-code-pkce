package com.authorizationservercode.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StartController {

	@GetMapping("/")
	public String teste() {
		return "teste";
	}
	
	@GetMapping("/authorize")
	public List<String> authorize(@RequestParam String code,
							@RequestParam String state) {
		
		List<String> retorno = new ArrayList<>();
		retorno.add("Código: "+code);
		retorno.add("State: "+state);
		
		System.out.println(retorno);
		return retorno;
	}
	
	@PostMapping("/authorize")
	public void salvar() {
		System.out.println("OK");
	}
}
