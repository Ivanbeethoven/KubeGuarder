package com.nanxing.webhookadmissioncontroller.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.nanxing.webhookadmissioncontroller.domin.audit.Event;
import com.nanxing.webhookadmissioncontroller.domin.webhook.AR_Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:25
 */
@RestController
@RequestMapping("/webhook")
@Slf4j
public class WebhookController {

    @Autowired
    private RestTemplate restTemplate;

    @PostMapping("/admission-review")
    public JSONObject receiveAdmissionReview(@RequestBody JSONObject admissionReviewJSONObject){
        forwardAdmissionReview(admissionReviewJSONObject);
        String uid = admissionReviewJSONObject.getJSONObject("request").getString("uid");
        admissionReviewJSONObject.put("response", JSON.toJSON(new AR_Response(uid, true)));
        return admissionReviewJSONObject;
    }

    private void forwardAdmissionReview(JSONObject admissionReviewJSONObject){
        String url = "http://localhost:8080/webhook/admission-review";
        try {
            restTemplate.postForObject(url, admissionReviewJSONObject, String.class);
            log.info("Admission Review has been forwarded");
        } catch (RestClientException e) {
            e.printStackTrace();
        }
    }

    //private void appendAdmissionReviewToFile(JSONObject admissionReview){
    //    String data = JSONObject.toJSONString(admissionReview);
    //    try (BufferedWriter writer = Files.newBufferedWriter(Paths.get("admission-reviews.txt"), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
    //        writer.write(data);
    //        writer.newLine(); // 确保每次写入后换行
    //    } catch (IOException e) {
    //        e.printStackTrace();
    //        // 处理异常，例如返回错误响应
    //    }
    //}

}
