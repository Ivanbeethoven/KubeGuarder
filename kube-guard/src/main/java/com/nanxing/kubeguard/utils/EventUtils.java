package com.nanxing.kubeguard.utils;

import com.alibaba.fastjson.JSONObject;

import java.io.*;
import java.util.*;

/**
 * Author: Nanxing
 * Date: 2024/4/13 23:09
 */
public class EventUtils {

    //获取审计日志中所有的资源访问
    public static void main(String[] args) {
        String eventDir = "audit-logs";
        String outputFolderPath = "access-record";

        Map<String, Set<String>> map = new HashMap<>();

        File folder = new File(eventDir);
        File[] files = folder.listFiles();

        if (files != null) {
            // 遍历每个文件
            for (File file : files) {
                System.out.println("Reading file: " + file.getName());
                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String line;
                    // 逐行读取文件内容
                    while ((line = reader.readLine()) != null) {
                        // 处理每一行内容，这里可以进行你想要的操作，比如打印或者解析
                        JSONObject eventObject = JSONObject.parseObject(line);
                        JSONObject user = eventObject.getJSONObject("user");
                        String username = user.getString("username");
                        if(!username.startsWith("system:serviceaccount:")){
                            break;
                        }
                        username = username.replace("system:serviceaccount:", "");
                        if(!map.containsKey(username)){
                            map.put(username, new HashSet<>());
                        }
                        Set<String> set = map.get(username);

                        //获取资源
                        if(!eventObject.containsKey("objectRef")){
                            break;
                        }
                        JSONObject objectRef = eventObject.getJSONObject("objectRef");
                        StringBuilder sb = new StringBuilder();
                        if(objectRef.containsKey("apiGroup")){
                            sb.append(objectRef.getString("apiGroup")).append("/");
                        }
                        if(objectRef.containsKey("apiVersion")){
                            sb.append(objectRef.getString("apiVersion")).append("/");
                        }

                        String kind = objectRef.getString("resource");
                        sb.append(kind).append("/");
                        if(objectRef.containsKey("name")){
                            sb.append(objectRef.getString("name")).append("/");
                        }

                        String namespace = null;
                        if(objectRef.containsKey("namespace")){
                            namespace = objectRef.getString("namespace");
                        }
                        sb.deleteCharAt(sb.length() - 1);
                        String resource = sb.toString();

                        String verb = eventObject.getString("verb");
                        if(namespace == null){
                            String signature = username.split(":")[1] + " " + resource + " " + verb;
                            set.add(signature);
                        }else{
                            String signature = username.split(":")[1]  + " " + resource + " " + namespace + " " + verb ;
                            set.add(signature);
                        }

                        //System.out.println(signature);
                    }
                } catch (IOException  e) {
                    System.err.println("Error reading file: " + e.getMessage());
                }

            }

            Set<String> keySet = map.keySet();
            for (String s : keySet) {
                Set<String> set = map.get(s);
                writeSetToFile(outputFolderPath, s.replace(":", "-"), set);
            }
        }

    }

    // 将Set<String>写入到文件中
    private static void writeSetToFile(String outputFolderPath, String fileName, Set<String> set) {
        File outputFile = new File(outputFolderPath + File.separator + fileName + ".txt");
        List<String> list = new ArrayList<>(set);
        // 对 List 进行排序
        Collections.sort(list);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            // 遍历Set，将每个元素写入文件中
            for (String value : list) {
                writer.write(value);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}



