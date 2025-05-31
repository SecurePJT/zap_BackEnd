package com.example.demo.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.example.demo.dto.AlertDto;
import com.example.demo.dto.ScanResult;

@Service
public class ScanService {

    private final ClientApi api = new ClientApi("localhost", 8090);
    private static final String DEFAULT_POLICY = "Default Policy";

    // 1) 공통 헬퍼 메서드

    private void clearAlerts() throws ClientApiException {
        api.core.deleteAllAlerts();
    }

    private void registerUrl(String targetUrl) throws ClientApiException, InterruptedException {
        api.core.accessUrl(targetUrl, "true");
        waitForPassiveScan();
    }

    private void setPassiveScanners(boolean enable) throws ClientApiException {
        if (enable) api.pscan.enableAllScanners(); else api.pscan.disableAllScanners();
    }

    private void startActiveScan(String targetUrl) throws ClientApiException {
        // 그대로 Default Policy에 설정된 스캐너들만 사용
        api.ascan.scan(targetUrl, "true", "false", DEFAULT_POLICY, null, null);
    }

    private ScanResult collectAlerts(String targetUrl) throws ClientApiException {
        List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
        List<AlertDto> alerts = zapAlerts.stream()
            .filter(a -> a.getUrl().startsWith(targetUrl))
            .map(a -> new AlertDto(
                    a.getRisk().toString(),
                    a.getName(),
                    a.getUrl(),
                    a.getParam(),
                    a.getEvidence()
            ))
            .collect(Collectors.toList());
        return new ScanResult(targetUrl, alerts.size(), alerts);
    }

    // 2) 폴링 대기 메서드 (로그 포함)

    private void waitForPassiveScan() throws InterruptedException, ClientApiException {
        int records;
        do {
            records = Integer.parseInt(((ApiResponseElement) api.pscan.recordsToScan()).getValue());
            System.out.println("Passive records to scan: " + records);
            Thread.sleep(500);
        } while (records > 0);
        System.out.println("Passive Scan 완료");
    }

    private void waitForActiveScan() throws InterruptedException, ClientApiException {
        String raw;
        int pct;
        do {
            raw = ((ApiResponseElement) api.ascan.status(null)).getValue();
            pct = Integer.parseInt(raw.replaceAll("\\D+", ""));
            System.out.println("Active Scan: " + pct + "%");
            Thread.sleep(1500);
        } while (pct < 100);
        System.out.println("Active Scan 완료");
    }

    private void waitForAjaxSpider() throws InterruptedException, ClientApiException {
        String status;
        do {
            status = ((ApiResponseElement) api.ajaxSpider.status()).getValue();
            System.out.println("AJAX Spider: " + status + "%");
            Thread.sleep(500);
        } while (!"100".equals(status) && !"stopped".equalsIgnoreCase(status));
        System.out.println("Ajax Spider 완료");
    }

    private void waitForSpider() throws InterruptedException, ClientApiException {
        int pct;
        String s;
        do {
            s = api.spider.status(null).toString();
            pct = Integer.parseInt(s.replaceAll("\\D+", ""));
            System.out.println("Spider: " + pct + "%");
            Thread.sleep(500);
        } while (pct < 100);
        System.out.println("Spider 완료");
    }

    // 3) 범용 스캔 메서드

    /**
     * @param targetUrl       스캔할 URL
     * @param crawl           크롤링 여부
     * @param active          Active Scan 여부
     * @param passive         Passive Scan 여부
     * @param activeScannerIds Active 스캐너 ID
     */
    public ScanResult performCustomScan(
        String targetUrl,
        boolean crawl,
        boolean active,
        boolean passive,
        List<String> activeScannerIds
    ) throws InterruptedException, ClientApiException {
        clearAlerts();

        // Passive 설정
        setPassiveScanners(passive);

        // 크롤링
        if (crawl) {
            api.ajaxSpider.scan(targetUrl, "60", "", "true");
            waitForAjaxSpider();
            api.spider.setOptionMaxDepth(5);
            api.spider.setOptionThreadCount(2);
            api.spider.scan(targetUrl, "", "true", "", "false");
            waitForSpider();
        }

        // Active Scan
        if (active) {
            // 스캔 트리에 URL 등록
            api.core.accessUrl(targetUrl, "true");
            if (passive) waitForPassiveScan();

            if (activeScannerIds != null && !activeScannerIds.isEmpty()) {
                // 특정 스캐너만 활성화
                api.ascan.disableAllScanners(DEFAULT_POLICY);
                api.ascan.enableScanners(String.join(",", activeScannerIds), DEFAULT_POLICY);
            }

            // Default Policy 설정 그대로 사용
            startActiveScan(targetUrl);
            waitForActiveScan();
        }

        return collectAlerts(targetUrl);
    }
}
