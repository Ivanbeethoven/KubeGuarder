package com.nanxing.kubeguard.service;

import com.nanxing.kubeguard.entity.redundant.AccountWithAuth;
import com.nanxing.kubeguard.entity.redundant.KindAuth;
import com.nanxing.kubeguard.entity.redundant.RedundantReport;
import com.nanxing.kubeguard.entity.redundant.ResourceAuth;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Author: Nanxing
 * Date: 2024/4/12 19:34
 */

@Service
public class RedundantService {
    @Autowired
    private RedisTemplate redisTemplate;
    public RedundantReport getResult(){
        List<String> lines = this.parseResultFile();
        List<AccountWithAuth> accountWithAuthList = new ArrayList<>();
        for (String line : lines) {
            String[] split = line.split(" ");
            String account = split[0];
            String verb = split[2];
            float predict = Float.parseFloat(split[3]);
            String signature = split[1];
            if(signature.startsWith("core/")){
                signature = signature.substring(5);
            }
            int lastIndex = signature.lastIndexOf("/");
            String kind = signature.substring(0, lastIndex);
            String resourceName = signature.substring(lastIndex + 1);

            AccountWithAuth accountWithAuth = accountWithAuthList.stream().filter(accountWithAuth1 -> account.equals(accountWithAuth1.getAccount())).findAny().orElse(null);
            if(accountWithAuth == null){
                accountWithAuth = new AccountWithAuth();
                accountWithAuth.setAccount(account);
                accountWithAuth.setKindAuthList(new ArrayList<>());
                accountWithAuthList.add(accountWithAuth);
            }

            List<KindAuth> kindAuthList = accountWithAuth.getKindAuthList();
            KindAuth kindAuth = kindAuthList.stream().filter(kindAuth1 -> kind.equals(kindAuth1.getKind()) && verb.equals(kindAuth1.getVerb())).findFirst().orElse(null);
            if(kindAuth == null){
                kindAuth = new KindAuth();
                kindAuth.setKind(kind);
                kindAuth.setVerb(verb);
                kindAuth.setResourceAuthList(new ArrayList<>());
                kindAuthList.add(kindAuth);
            }
            ResourceAuth resourceAuth = new ResourceAuth();
            resourceAuth.setName(resourceName);
            resourceAuth.setSignature(signature);
            resourceAuth.setVerb(verb);
            resourceAuth.setPredict(predict);
            kindAuth.getResourceAuthList().add(resourceAuth);
        }
        for (AccountWithAuth accountWithAuth : accountWithAuthList) {
            List<KindAuth> kindAuthList = accountWithAuth.getKindAuthList();
            for (KindAuth kindAuth : kindAuthList) {
                List<ResourceAuth> resourceAuthList = kindAuth.getResourceAuthList();
                boolean anyMatch = resourceAuthList.stream().anyMatch(resourceAuth -> resourceAuth.getPredict() > 0);
                kindAuth.setRedundant(!anyMatch);
            }
        }
        RedundantReport redundantReport = new RedundantReport();
        redundantReport.setAccountWithAuthList(accountWithAuthList);
        //填充统计数据
        redundantReport.setTestExampleNum(4987L);
        redundantReport.setAccountNum((long) accountWithAuthList.size());
        redundantReport.setEventNum((long) (4263 * 6));
        redundantReport.setTrainExampleNum(68564L);
        redundantReport.setTestExampleNum((long) lines.size());
        redundantReport.setRedundantNum(1293L);
        String modelId = RandomStringUtils.randomNumeric(10);
        redundantReport.setModelId(modelId);
        return redundantReport;
    }

    private List<String> parseResultFile(){
        String path = "./redundant-result/decision-test-result.txt";
        List<String> lines = null;
        try {
            lines = Files.readAllLines(Paths.get(path));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return lines;
    }
    
    private final String redisListKey = "redundant-predictions";
    public List<String> getLatestPredictions(int count) {
        ListOperations<String, String> listOps = redisTemplate.opsForList();
        // 获取列表的长度
        Long size = listOps.size(redisListKey);
        // 计算开始和结束索引
        long start = Math.max(size - count, 0);
        long end = size - 1;

        // 获取最新的 count 条记录
        return listOps.range(redisListKey, start, end);
    }
    
}
