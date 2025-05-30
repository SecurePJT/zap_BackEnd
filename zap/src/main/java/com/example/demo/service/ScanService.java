package com.example.demo.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.example.demo.dto.AlertDto;
import com.example.demo.dto.ScanResult;

@Service
public class ScanService {

	private final ClientApi api = new ClientApi("localhost", 8090);

	/**
	 * 1) AJAX + Spider 크롤링 후 Active Scan → Passive 룰도 모두 활성화
	 */
	public ScanResult performScan(String targetUrl) throws InterruptedException, ClientApiException {
		// 기존 Alert 삭제
		api.core.deleteAllAlerts();

		System.out.println("진입0 (full scan)");

		// 모든 Passive 스캐너 활성화
		api.pscan.enableAllScanners();

		// AJAX Spider
		api.ajaxSpider.scan(targetUrl, "60", "", "true");
		waitForAjaxSpider();

		// 전통 Spider
		api.spider.setOptionMaxDepth(5);
		api.spider.setOptionThreadCount(2);
		api.spider.scan(targetUrl, "", "true", "", "false");
		waitForSpider();

		// Active Scan
		api.ascan.scan(targetUrl, "true", "false", "Default Policy", null, null);
		waitForActiveScan();

		// Alerts 수집 (Passive + Active)
		List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
		List<AlertDto> alerts = mapToDto(targetUrl, zapAlerts);

		return new ScanResult(targetUrl, alerts.size(), alerts);
	}

	/**
	 * 2) AJAX + Spider 크롤링 후 Passive Scan 결과만 반환
	 */
	public ScanResult performPassiveScan(String targetUrl) throws InterruptedException, ClientApiException {
		// 기존 Alert 삭제
		api.core.deleteAllAlerts();

		System.out.println("진입0 (Passive)");

		// AJAX Spider
		api.ajaxSpider.scan(targetUrl, "60", "", "true");
		waitForAjaxSpider();

		// 전통 Spider
		api.spider.setOptionMaxDepth(5);
		api.spider.setOptionThreadCount(2);
		api.spider.scan(targetUrl, "", "true", "", "false");
		waitForSpider();

		// Alerts 수집 (Passive)
		List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
		List<AlertDto> alerts = mapToDto(targetUrl, zapAlerts);

		return new ScanResult(targetUrl, alerts.size(), alerts);
	}

	/**
	 * 3) Active Scan만 별도 실행
	 */
	public ScanResult performActiveScan(String targetUrl) throws InterruptedException, ClientApiException {
		// 기존 Alert 삭제
		api.core.deleteAllAlerts();

		System.out.println("진입0 (Active)");

		// 1) Site Tree에 URL을 추가
		api.core.accessUrl(targetUrl, "true"); // followRedirects = true
		waitForPassiveScan();

		api.ascan.scan(targetUrl, "true", "false", "Default Policy", null, null);
		waitForActiveScan();

		// Alerts 수집 (Active + Passive)
		List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
		List<AlertDto> alerts = mapToDto(targetUrl, zapAlerts);

		return new ScanResult(targetUrl, alerts.size(), alerts);
	}

	/**
	 * 4) 크롤링 없이 단일 URL → Passive Scan만
	 */
	public ScanResult performPassiveNoCrawl(String targetUrl) throws InterruptedException, ClientApiException {
		// 기존 Alert 삭제
		api.core.deleteAllAlerts();

		System.out.println("진입0 (PassiveNoCrawl)");

		// 모든 Passive 스캐너 활성화
		api.pscan.enableAllScanners();

		// 단일 URL 요청 (Passive 룰 적용)
		api.core.accessUrl(targetUrl, "true");
		waitForPassiveScan();

		// Alerts 수집 (Passive)
		List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
		List<AlertDto> alerts = mapToDto(targetUrl, zapAlerts);

		return new ScanResult(targetUrl, alerts.size(), alerts);
	}

	/**
	 * 5) SQLi(40018)와 XSS(40012)만 활성화 후 Active Scan
	 */
	public ScanResult performTop3Scan(String targetUrl) throws InterruptedException, ClientApiException {
		// 기존 Alert 삭제
		api.core.deleteAllAlerts();

		System.out.println("진입0 (Top3 Scan)");

		String policy = "Default Policy";

		// Passive 스캐너 비활성화
		api.pscan.disableAllScanners();

		// 모든 Active 스캐너 비활성화
		api.ascan.disableAllScanners(policy);

		// SQLi와 XSS 스캐너만 활성화
		api.ascan.enableScanners("40018,40012", policy);

		// Active Scan 시작
		api.ascan.scan(targetUrl, "true", "false", policy, null, null);

		// 스캔 진행률 대기 및 출력
		int pct;
		do {
			ApiResponse resp = api.ascan.status(null);
			String raw = (resp instanceof ApiResponseElement) ? ((ApiResponseElement) resp).getValue()
					: resp.toString();
			pct = Integer.parseInt(raw.replaceAll("\\D+", ""));
			System.out.println("Top3 Active Scan: " + pct + "%");
			Thread.sleep(1500);
		} while (pct < 100);
		System.out.println("Top3 Active Scan 완료");

		// Alerts 수집 (Active)
		List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
		List<AlertDto> alerts = mapToDto(targetUrl, zapAlerts);

		return new ScanResult(targetUrl, alerts.size(), alerts);
	}

	// ────────────────────────────────────────────
	// Polling helper methods
	// ────────────────────────────────────────────

	private void waitForAjaxSpider() throws InterruptedException, ClientApiException {
		String status;
		do {
			ApiResponse resp = api.ajaxSpider.status();
			status = (resp instanceof ApiResponseElement) ? ((ApiResponseElement) resp).getValue() : resp.toString();
			System.out.println("AJAX Spider: " + status + "%");
			Thread.sleep(500);
		} while (!"100".equals(status) && !"stopped".equalsIgnoreCase(status));
		System.out.println("Ajax Spider 완료");
	}

	private void waitForSpider() throws InterruptedException, ClientApiException {
		String s;
		do {
			s = api.spider.status(null).toString();
			System.out.println("Spider: " + s + "%");
			Thread.sleep(500);
		} while (Integer.parseInt(s.replaceAll("\\D+", "")) < 100);
		System.out.println("Spider 완료");
	}

	private void waitForActiveScan() throws InterruptedException, ClientApiException {
		String raw;
		int pct;
		do {
			ApiResponse resp = api.ascan.status(null);
			raw = (resp instanceof ApiResponseElement) ? ((ApiResponseElement) resp).getValue() : resp.toString();
			pct = Integer.parseInt(raw.replaceAll("\\D+", ""));
			System.out.println("Active Scan: " + pct + "%");
			Thread.sleep(2000);
		} while (pct < 100);
		System.out.println("Active Scan 완료");
	}

	private void waitForPassiveScan() throws InterruptedException, ClientApiException {
		int records;
		do {
			String v = ((ApiResponseElement) api.pscan.recordsToScan()).getValue();
			records = Integer.parseInt(v);
			System.out.println("Passive records to scan: " + records);
			Thread.sleep(500);
		} while (records > 0);
		System.out.println("Passive Scan 완료");
	}

	private List<AlertDto> mapToDto(String targetUrl, List<Alert> zapAlerts) {
		return zapAlerts.stream().filter(a -> a.getUrl().startsWith(targetUrl))
				.map(z -> new AlertDto(z.getRisk().toString(), z.getName(), z.getUrl(), z.getParam(), z.getEvidence()))
				.collect(Collectors.toList());
	}
}
