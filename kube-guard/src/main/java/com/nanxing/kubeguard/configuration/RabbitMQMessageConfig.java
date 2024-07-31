package com.nanxing.kubeguard.configuration;

import org.springframework.amqp.core.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Author: Nanxing
 * Date: 2024/3/20 17:43
 */
@Configuration
public class RabbitMQMessageConfig {
    /**
     * 订单交换机
     */
    public static final String PACKET_EXCHANGE = "packet_exchange";
    /**
     * 订单队列
     */
    public static final String PACKET_QUEUE = "packet_queue";
    /**
     * 订单路由key
     */
    public static final String PACKET_QUEUE_ROUTING_KEY = "packet.#";

    /**
     * 死信交换机
     */
    public static final String PACKET_DEAD_LETTER_EXCHANGE = "packet_dead_letter_exchange";
    /**
     * 死信队列 routingKey
     */
    public static final String PACKET_DEAD_LETTER_QUEUE_ROUTING_KEY = "packet_dead_letter_queue_routing_key";

    /**
     * 死信队列
     */
    public static final String PACKET_DEAD_LETTER_QUEUE = "packet_dead_letter_queue";

    /**
     * 延迟时间 （单位：ms(毫秒)）
     */
    public static final Integer DELAY_TIME = 60000;

    /**
     * 创建死信交换机
     */
    @Bean("packetDeadLetterExchange")
    public Exchange orderDeadLetterExchange() {
        return new TopicExchange(PACKET_DEAD_LETTER_EXCHANGE, true, false);
    }

    /**
     * 创建死信队列
     */
    @Bean("packetDeadLetterQueue")
    public Queue orderDeadLetterQueue() {
        return QueueBuilder.durable(PACKET_DEAD_LETTER_QUEUE).build();
    }

    /**
     * 绑定死信交换机和死信队列
     */
    @Bean("packetDeadLetterBinding")
    public Binding orderDeadLetterBinding(@Qualifier("packetDeadLetterQueue") Queue queue, @Qualifier("packetDeadLetterExchange")Exchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(PACKET_DEAD_LETTER_QUEUE_ROUTING_KEY).noargs();
    }


    /**
     * 创建订单交换机
     */
    @Bean("packetExchange")
    public Exchange orderExchange() {
        return new TopicExchange(PACKET_EXCHANGE, true, false);
    }

    /**
     * 创建订单队列
     */
    @Bean("packetQueue")
    public Queue orderQueue() {
        Map<String, Object> args = new HashMap<>(3);
        //消息过期后，进入到死信交换机
        args.put("x-dead-letter-exchange", PACKET_DEAD_LETTER_EXCHANGE);

        //消息过期后，进入到死信交换机的路由key
        args.put("x-dead-letter-routing-key", PACKET_DEAD_LETTER_QUEUE_ROUTING_KEY);

        //过期时间，单位毫秒
        args.put("x-message-ttl", DELAY_TIME);

        return QueueBuilder.durable(PACKET_QUEUE).withArguments(args).build();
    }

    /**
     * 绑定订单交换机和队列
     */
    @Bean("packetBinding")
    public Binding orderBinding(@Qualifier("packetQueue") Queue queue, @Qualifier("packetExchange")Exchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(PACKET_QUEUE_ROUTING_KEY).noargs();
    }


}
