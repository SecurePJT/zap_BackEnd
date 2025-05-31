package com.example.demo.controller;

import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.example.demo.dto.ScanRequest;
import com.example.demo.dto.ScanResult;
import com.example.demo.service.ScanService;

@RestController
public class ScanController {

	private final ScanService scanService;

	public ScanController(ScanService scanService) {
		this.scanService = scanService;
	}

	// ───────────────────────────────────────────────────────────────────────────
	// 6가지 [크롤링 × 액티브 × 패시브] 조합
	// ───────────────────────────────────────────────────────────────────────────

	// 1) O / O / O
	// 예제 사이트 분석결과: 419
	@PostMapping("/crawl-active-passive")
	public ResponseEntity<ScanResult> crawlActivePassive(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, true, true, null);
		return ResponseEntity.ok(result);
	}

	// 2) O / O / X
	// 예제 사이트 분석결과: 14
	@PostMapping("/crawl-active")
	public ResponseEntity<ScanResult> crawlActive(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, true, false, null);
		return ResponseEntity.ok(result);
	}

	// 3) O / X / O
	// 예제 사이트 분석결과: 403
	@PostMapping("/crawl-passive")
	public ResponseEntity<ScanResult> crawlPassive(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, false, true, null);
		return ResponseEntity.ok(result);
	}

	// 4) X / O / O
	// 예제 사이트 분석결과: 19
	@PostMapping("/active-passive")
	public ResponseEntity<ScanResult> activePassive(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, true, true, null);
		return ResponseEntity.ok(result);
	}

	// 5) X / O / X
	// 예제 사이트 분석결과: 12
	@PostMapping("/active")
	public ResponseEntity<ScanResult> activeOnly(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, true, false, null);
		return ResponseEntity.ok(result);
	}

	// 6) X / X / O
	// 예제 사이트 분석결과: 0
	@PostMapping("/passive")
	public ResponseEntity<ScanResult> passiveOnly(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, false, true, null);
		return ResponseEntity.ok(result);
	}

	// ───────────────────────────────────────────────────────────────────────────
	// 6가지 [크롤링 × SQL/XSS 스캐너 필터] 조합
	// ───────────────────────────────────────────────────────────────────────────

	// 7) 크롤링 O, SQL+XSS
	// 예제 사이트 분석결과: 23
	@PostMapping("/crawl-sqlxss")
	public ResponseEntity<ScanResult> crawlSqlXss(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, true, false, List.of("40018", "40012"));
		return ResponseEntity.ok(result);
	}

	// 8) 크롤링 O, SQL만
	// 예제 사이트 분석결과: 9
	@PostMapping("/crawl-sql")
	public ResponseEntity<ScanResult> crawlSql(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, true, false, List.of("40018"));
		return ResponseEntity.ok(result);
	}

	// 9) 크롤링 O, XSS만
	// 예제 사이트 분석결과: 10
	@PostMapping("/crawl-xss")
	public ResponseEntity<ScanResult> crawlXss(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), true, true, false, List.of("40012"));
		return ResponseEntity.ok(result);
	}

	// 10) 크롤링 X, SQL+XSS
	// 예제 사이트 분석결과: 24
	@PostMapping("/sqlxss")
	public ResponseEntity<ScanResult> sqlXss(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, true, false, List.of("40018", "40012"));
		return ResponseEntity.ok(result);
	}

	// 11) 크롤링 X, SQL만
	// 예제 사이트 분석결과: 11
	@PostMapping("/sql")
	public ResponseEntity<ScanResult> sqlOnly(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, true, false, List.of("40018"));
		return ResponseEntity.ok(result);
	}

	// 12) 크롤링 X, XSS만
	// 예제 사이트 분석결과: 12
	@PostMapping("/xss")
	public ResponseEntity<ScanResult> xssOnly(@RequestBody ScanRequest req) throws Exception {
		ScanResult result = scanService.performCustomScan(req.getUrl(), false, true, false, List.of("40012"));
		return ResponseEntity.ok(result);
	}

	@GetMapping("/version")
	public ResponseEntity<String> zapVersion() throws ClientApiException {
		String version = new ClientApi("localhost", 8090).core.version().toString();
		return ResponseEntity.ok("ZAP version: " + version);
	}
}
