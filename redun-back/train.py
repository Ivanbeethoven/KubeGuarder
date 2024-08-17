from data_generate import *
from feature_utils import *

# #生成数据集
# generate_train_data()
# generate_test_data()

# #特征提取与打标签
# get_labeled("./train-dataset/positive", "./train-dataset/negative")
# get_test("./test-dataset")

#训练模型
import pandas as pd
from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments
from torch.utils.data import Dataset
import torch
from sklearn.model_selection import train_test_split

class TextDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]
        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

# 加载数据
train_df = pd.read_csv('./train-dataset/labeled_train_data.csv')
#test_df = pd.read_csv('./test-dataset/test_data.csv')

# 分离文本和标签
texts = train_df['text'].values
labels = train_df['label'].values

train_texts, val_texts, train_labels, val_labels = train_test_split(texts, labels, test_size=0.2, random_state=42)

#test_texts = test_df['text'].values


# 定义tokenizer和参数
tokenizer = BertTokenizer.from_pretrained('./bert-base-uncased')
MAX_LENGTH = 512

# 创建Dataset对象
train_dataset = TextDataset(train_texts, train_labels, tokenizer, MAX_LENGTH)
val_dataset = TextDataset(val_texts, val_labels, tokenizer, MAX_LENGTH)

model = BertForSequenceClassification.from_pretrained('./bert-base-uncased', num_labels=2)

training_args = TrainingArguments(
    output_dir='./results',
    num_train_epochs=3,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    warmup_steps=500,
    weight_decay=0.01,
    logging_dir='./logs',
    logging_steps=10,
    evaluation_strategy="steps",
    save_steps=20,
    save_total_limit=10,
    load_best_model_at_end=True,
    fp16 = True
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
)
trainer.train()
results = trainer.evaluate()
print(results)
