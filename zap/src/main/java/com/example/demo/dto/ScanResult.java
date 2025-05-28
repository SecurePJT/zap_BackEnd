package com.example.demo.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ScanResult {
	private String targetUrl;
    private List<AlertDto> alerts;
}
