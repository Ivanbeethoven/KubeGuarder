from transformers import BertTokenizer, BertForSequenceClassification
import torch
import pandas as pd

test_df = pd.read_csv('./test-dataset/test_data.csv')
test_texts = test_df['text'].values
test_lable = test_df['label'].values
# 加载模型和tokenizer
model_path = './results/checkpoint-300'  # 训练好的模型保存路径
tokenizer = BertTokenizer.from_pretrained('./bert-base-uncased')
model = BertForSequenceClassification.from_pretrained(model_path)

# 设置模型为评估模式
model.eval()

def predict(text, model, tokenizer, max_length=128):
    # 将文本编码为BERT输入格式
    encoding = tokenizer.encode_plus(
        text,
        add_special_tokens=True,
        max_length=max_length,
        return_token_type_ids=False,
        padding='max_length',
        truncation=True,
        return_attention_mask=True,
        return_tensors='pt',
    )

    input_ids = encoding['input_ids']
    attention_mask = encoding['attention_mask']

    # 使用GPU（如果可用）
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    input_ids = input_ids.to(device)
    attention_mask = attention_mask.to(device)

    # 不计算梯度的情况下进行前向传播
    with torch.no_grad():
        outputs = model(input_ids, attention_mask=attention_mask)
        logits = outputs.logits

    # 获取预测结果
    predicted_class_id = torch.argmax(logits, dim=1).item()
    return predicted_class_id



# count = 0
# all_len = len(test_texts)
# for index, text in enumerate(test_texts):
#     # 进行预测
#     predicted_class_id = predict(text, model, tokenizer)
#     if predicted_class_id == test_lable[index]:
#         count+=1

# print("totol acc:{}", float(count) /float(all_len))

# 打开文件
with open('audit.log', 'r') as file:
    # 遍历文件的每一行
    for line in file:
        # 去除行末的换行符
        line = line.strip()
        # 处理每一行
        predicted_class_id = predict(line, model, tokenizer)
        if predicted_class_id ==1:
            print("test:{}, classh:{}",line,predicted_class_id)