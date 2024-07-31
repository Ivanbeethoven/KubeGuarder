package com.nanxing.kubeguard.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.nanxing.kubeguard.entity.audit.Event;
import com.nanxing.kubeguard.entity.webhook.AR_Response;
import com.nanxing.kubeguard.entity.webhook.AdmissionReview;
import com.nanxing.kubeguard.service.PrivilegeEscalationDetectionService;
import com.nanxing.kubeguard.service.SensitiveResourceDetectionService;
import io.kubernetes.client.proto.V1Admission;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:25
 */
@RestController
@Slf4j
public class ResourceOperationReceiver {

    @Autowired
    private PrivilegeEscalationDetectionService privilegeEscalationDetectionService;

    @Autowired
    private SensitiveResourceDetectionService sensitiveResourceDetectionService;

    @PostMapping("/webhook/event")
    public void receiveAuditEvent(@RequestBody JSONObject jsonObject){
        if(jsonObject == null){
            return;
        }
        if(!jsonObject.containsKey("items")){
            return;
        }
        JSONArray jsonArray = jsonObject.getJSONArray("items");
        int size = jsonArray.size();
        log.info("Received [{}] audit events", size);
        List<Event> eventList = jsonArray.toJavaList(Event.class);
        for (Event event : eventList) {
            System.out.println(event.getUser().getUsername() + "  " + event.getRequestURI());
            //appendEventToFile(event);
            privilegeEscalationDetectionService.detectEvent(event);
            sensitiveResourceDetectionService.extractKeywordsFromEvent(event);
        }
    }

    //private void appendEventToFile(Object object){
    //    String data = JSONObject.toJSONString(object);
    //    try (BufferedWriter writer = Files.newBufferedWriter(Paths.get("event-list.txt"), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
    //        writer.write(data);
    //        writer.newLine(); // 确保每次写入后换行
    //    } catch (IOException e) {
    //        e.printStackTrace();
    //        // 处理异常，例如返回错误响应
    //    }
    //}

    @PostMapping("/webhook/admission-review")
    public String receiveAdmissionReview(@RequestBody JSONObject admissionReviewJSONObject){
        //appendAdmissionReviewToFile(admissionReviewJSONObject);
        privilegeEscalationDetectionService.detectAdmissionReview(admissionReviewJSONObject);
        return "success";
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
