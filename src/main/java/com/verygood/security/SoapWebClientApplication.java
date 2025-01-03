package com.verygood.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SoapWebClientApplication {

	static {
		org.apache.xml.security.Init.init();
	}

	public static void main(String[] args) {
		SpringApplication.run(SoapWebClientApplication.class, args);
	}

}
