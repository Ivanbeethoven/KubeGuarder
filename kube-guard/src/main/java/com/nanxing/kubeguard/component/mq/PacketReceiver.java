package com.nanxing.kubeguard.component.mq;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.nanxing.kubeguard.configuration.RabbitMQMessageConfig;
import com.nanxing.kubeguard.entity.keywordmatching.SensitivityResourceLeakageDetectionReport;
import com.nanxing.kubeguard.entity.keywordmatching.ServiceAccountAndIPs;
import com.nanxing.kubeguard.service.SensitiveResourceDetectionService;
import com.nanxing.kubeguard.utils.RedisCache;
import com.nanxing.kubeguard.websocket.SensitiveWebSocketServer;
import com.rabbitmq.client.Channel;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitHandler;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;

/**
 * Author: Nanxing
 * Date: 2024/3/20 17:56
 */
@Component
@RabbitListener(queues = RabbitMQMessageConfig.PACKET_DEAD_LETTER_QUEUE)
@Slf4j
public class PacketReceiver {
    @Autowired
    private SensitiveResourceDetectionService sensitiveResourceDetectionService;

    @Autowired
    private RedisCache redisCache;

    //统计接收的流量
    private long judgedLeaked = 0;
    private long allReceived = 0;

    @RabbitHandler
    public void consumer(JSONObject packet, Message message, Channel channel) throws IOException {

        SensitivityResourceLeakageDetectionReport report = sensitiveResourceDetectionService.processPacket(packet);
        String id = packet.getString("id");
        if(id.contains("/")){
            id = id.substring(id.indexOf("/") + 1);
        }
        allReceived++;
        JSONObject request = packet.getJSONObject("request");
        String url = request.getString("url");

        if(report.isLeakage()){
            toRedis("kube-guard:sensitive-resource-detection:" + id, report);
            //发送至前端
            sendReportToWSClient(report);
            judgedLeaked++;
            log.warn("There are risks of resource leakage in stream [{}]", id);
        }else{
            log.info("No risk of resource leakage in stream [{}].", id);
        }
        System.out.println("============================================");
        System.out.println("All received: " + allReceived);
        System.out.println("Judged Leaked: " + judgedLeaked);
    }

    @Async
    public void toRedis(String key, JSONObject packet){
        redisCache.setCacheObject(key, packet);
    }

    @Async
    public void toRedis(String key, SensitivityResourceLeakageDetectionReport report){
        redisCache.setCacheObject(key, report);
    }

    @Async
    public void sendReportToWSClient(SensitivityResourceLeakageDetectionReport report){
        try {
            SensitiveWebSocketServer.sendMessage(JSON.toJSONString(report), null);
        } catch (IOException e) {
            log.error("发送检测结果失败！");
            e.printStackTrace();
        }

    }




}
