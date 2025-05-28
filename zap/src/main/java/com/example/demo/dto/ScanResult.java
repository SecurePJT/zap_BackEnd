package com.example.demo.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanResult {
    private String targetUrl;
    private int alertCount;       // 새로 추가된 필드
    private List<AlertDto> alerts;
}