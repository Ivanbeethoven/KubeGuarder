package com.nanxing.kubeguard.controller;

import com.nanxing.kubeguard.entity.keywordmatching.SensitiveDTO;
import com.nanxing.kubeguard.entity.keywordmatching.SensitivityResourceLeakageDetectionReport;
import com.nanxing.kubeguard.entity.redundant.RedundantReport;
import com.nanxing.kubeguard.entity.runtimecheck.DynamicDTO;
import com.nanxing.kubeguard.entity.runtimecheck.DynamicDetectionReport;
import com.nanxing.kubeguard.service.RedundantService;
import com.nanxing.kubeguard.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Author: Nanxing
 * Date: 2024/4/11 21:48
 */
@RestController
@CrossOrigin
public class FrontController {

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private RedundantService redundantService;

    @GetMapping("/escalation/results")
    public List<DynamicDTO> getEscalationResult(){
        List<DynamicDetectionReport> list =
                redisTemplate.opsForList().range("kube-guard:dynamic-detection:escalation-reports", -30, -1);

        return list.stream()
                .map(DynamicDTO::new)
                .collect(Collectors.toList());

    }

    @GetMapping("/sensitive/results")
    public List<SensitiveDTO> getSensitiveResult(){
        Collection<String> keys = redisCache.keys("kube-guard:sensitive-resource-detection:*");
        List<SensitiveDTO> list = new ArrayList<>();
        for (String key : keys) {
            SensitivityResourceLeakageDetectionReport report = redisCache.getCacheObject(key);
            SensitiveDTO sensitiveDTO = new SensitiveDTO(report);
            list.add(sensitiveDTO);
        }
        return list;
    }


    @GetMapping("/redundant/results")
    public RedundantReport getRedundantResult(){
        return redundantService.getResult();

    }
    @GetMapping("/redundant/latest-predictions")
    public List<String> getLatestPredictions(@RequestParam(defaultValue = "30") int count) {
        return redundantService.getLatestPredictions(count);
    }



}
