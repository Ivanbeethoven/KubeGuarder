package com.nanxing.kubeguard.component.mq;

import com.alibaba.fastjson.JSONObject;
import com.nanxing.kubeguard.configuration.RabbitMQMessageConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Author: Nanxing
 * Date: 2024/3/20 17:52
 */
@Component
@Slf4j
public class PacketSender {
    @Autowired
    private RabbitTemplate rabbitTemplate;

    private long count = 0;

    public void sendOrderMessage(JSONObject packet) {
        //为true,则交换机处理消息到路由失败，则会返回给生产者 配置文件指定，则这里不需指定
        rabbitTemplate.setMandatory(true);
        //开启强制消息投递（mandatory为设置为true），但消息未被路由至任何一个queue，则回退一条消息
        rabbitTemplate.setReturnsCallback(returned -> {
            int code = returned.getReplyCode();
            System.out.println("code=" + code);
            System.out.println("returned=" + returned);
        });
        rabbitTemplate.convertAndSend(RabbitMQMessageConfig.PACKET_EXCHANGE, "packet", packet);
        count++;
        //log.info("===============延时队列生产消息 ({})====================", count);
        //log.info("发送时间:{}, {}ms后执行", LocalDateTime.now(), RabbitMQMessageConfig.DELAY_TIME);
    }

}
