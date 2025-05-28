package com.example.demo.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.example.demo.dto.ScanRequest;
import com.example.demo.dto.ScanResult;
import com.example.demo.service.ScanService;

@RestController
public class ScanController {

	private final ScanService scanService;
	private final ClientApi api = new ClientApi("localhost", 8090);

	public ScanController(ScanService scanService) {
		this.scanService = scanService;
	}

	// zap 버전 확인
	@GetMapping("/zap/version")
	public ResponseEntity<String> zapVersion() {
		try {
			// ZAP core.version API 호출
			ApiResponse resp = api.core.version();
			String version = ((ApiResponseElement) resp).getValue();
			return ResponseEntity.ok("ZAP version: " + version);
		} catch (ClientApiException e) {
			return ResponseEntity.status(502).body("Failed to connect to ZAP: " + e.getMessage());
		}
	}

	// Ajax Spider와 전통 Spider 크롤링 후 Active Scan
	@PostMapping("/scan")
	public ResponseEntity<ScanResult> scan(@RequestBody ScanRequest req) throws Exception {
		// 1) 유효성 검사 (SSRF 방지 등)
		if (!req.getUrl().startsWith("http")) {
			return ResponseEntity.badRequest().build();
		}
		// 2) 스캔 시작 & 결과 반환
		ScanResult result = scanService.performScan(req.getUrl());
		return ResponseEntity.ok(result);
	}

	// AJAX + 전통 Spider 크롤링 후 패시브 스캔 결과만 반환
	@PostMapping("/performPassiveScan")
	public ResponseEntity<ScanResult> performPassiveScan(@RequestBody ScanRequest req) throws Exception {
		// 1) 유효성 검사 (SSRF 방지 등)
		if (!req.getUrl().startsWith("http")) {
			return ResponseEntity.badRequest().build();
		}
		// 2) 스캔 시작 & 결과 반환
		ScanResult result = scanService.performPassiveScan(req.getUrl());
		return ResponseEntity.ok(result);
	}

	// 크롤링x Active Scan만 별도로 실행
	@PostMapping("/performActiveScan")
	public ResponseEntity<ScanResult> performActiveScan(@RequestBody ScanRequest req) throws Exception {
		// 1) 유효성 검사 (SSRF 방지 등)
		if (!req.getUrl().startsWith("http")) {
			return ResponseEntity.badRequest().build();
		}
		// 2) 스캔 시작 & 결과 반환
		ScanResult result = scanService.performActiveScan(req.getUrl());
		return ResponseEntity.ok(result);
	}
	
	// 크롤링 없이 URL 단건 요청만으로 패시브 스캔
	@PostMapping("/performPassiveNoCrawl")
    public ResponseEntity<ScanResult> performPassiveNoCrawl(@RequestBody ScanRequest req) throws Exception {
        if (!req.getUrl().startsWith("http")) {
            return ResponseEntity.badRequest().build();
        }
        ScanResult result = scanService.performPassiveNoCrawl(req.getUrl());
        return ResponseEntity.ok(result);
    }

}
