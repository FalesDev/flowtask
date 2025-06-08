package com.falesdev.flowtask;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class FlowtaskApplication {

	public static void main(String[] args) {
		SpringApplication.run(FlowtaskApplication.class, args);
	}

}
