package com.example.demo.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.example.demo.dto.AlertDto;
import com.example.demo.dto.ScanResult;

@Service
public class ScanService {

	private final ClientApi api = new ClientApi("localhost", 8090);

    public ScanResult performScan(String targetUrl)
            throws InterruptedException, ClientApiException {
    	
    	System.out.println("진입0");

    	// 1) Ajax Spider 실행
    	api.ajaxSpider.scan(targetUrl, "60", "", "true");

    	// 2) 상태 폴링
    	String ajaxStatus;
    	do {
    	    ApiResponse resp = api.ajaxSpider.status();                              // ApiResponse 객체 획득
    	    if (resp instanceof ApiResponseElement) {
    	        ajaxStatus = ((ApiResponseElement) resp).getValue();                 // 문자열 값 추출
    	    } else {
    	        // 혹시 다른 응답 타입이 오면 toString()으로라도 처리
    	        ajaxStatus = resp.toString();
    	    }
    	    System.out.println("AJAX Spider: " + ajaxStatus + "%");
    	    Thread.sleep(500);
    	} while (!"100".equals(ajaxStatus) && !"stopped".equalsIgnoreCase(ajaxStatus));

    	System.out.println("Ajax Spider 완료 (" + ajaxStatus + ")");

        System.out.println("진입1");

        // 2) 전통 Spider (HTML 링크 크롤링)
        api.spider.setOptionMaxDepth(5);
        api.spider.setOptionThreadCount(2);
        api.spider.scan(
            targetUrl,    // 1) URL
            "",           // 2) maxChildren: 빈 문자열이면 무제한
            "true",       // 3) recurse: 깊이 크롤링 여부
            "",           // 4) contextName: 빈 문자열이면 global
            "false"       // 5) subtreeOnly: 전체 사이트 크롤링 여부
        );
        while (Integer.parseInt(api.spider.status(null).toString()) < 100) {
        	System.out.println(api.spider.status(null).toString() + "% 2");
            Thread.sleep(500);
        }

        System.out.println("진입2");

     // 3) Active Scan (공격 테스트)
        api.ascan.scan(
            targetUrl,        // URL
            "true",           // recurse
            "false",          // inScopeOnly
            "Default Policy", // scanPolicyName
            null,             // method
            null              // postData
        );

        // 상태 폴링
        while (true) {
            ApiResponse resp = api.ascan.status(null);
            String raw = resp instanceof ApiResponseElement
                ? ((ApiResponseElement) resp).getValue()
                : resp.toString();
            // raw 예: "0%", "12%", "100%"
            String digits = raw.replaceAll("\\D+", "");  // 숫자 외 전부 제거
            int pct = digits.isEmpty() ? 0 : Integer.parseInt(digits);

            System.out.println("Active Scan: " + pct + "%");
            if (pct >= 100) {
                break;
            }
            Thread.sleep(2000);
        }
        System.out.println("Active Scan 완료");

        // 4) Alerts 수집
        List<Alert> zapAlerts = api.getAlerts(null, 0, 9999);
        System.out.println("진입4");

        // 5) DTO 매핑
        List<AlertDto> alerts = zapAlerts.stream()
            .filter(a -> a.getUrl().startsWith(targetUrl))
            .map(z -> new AlertDto(
                z.getRisk().toString(),
                z.getName(),
                z.getUrl(),
                z.getParam(),
                z.getEvidence()
            ))
            .collect(Collectors.toList());

        return new ScanResult(targetUrl, alerts);
    }


}
