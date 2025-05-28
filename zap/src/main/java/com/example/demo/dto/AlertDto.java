package com.example.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AlertDto {
	private String risk;
    private String name;
    private String uri;
    private String param;
    private String evidence;
}
