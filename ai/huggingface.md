[toc]

# Huggingface入门指南（NLP）

## 安装

```bash
pip install transformers datasets
```

## NLP数据集构建

### 数据集下载

在`huggingface`中，我们可以使用`load_dataset`函数来下载数据集：

```python
from datasets import load_dataset

dataset = load_dataset('glue', 'mrpc', split='train')
```

在上面，我们使用了三个参数，下面是详细描述：

```tex
第一个参数：
'glue'是要下载的数据集名称。若这个字符串填写为本地的路径，那么会使用本地的数据集。
第二个参数：
'mrpc'是数据集的`config`名称。在huggingface中，可以使用config来设置数据集的一些参数。
例如，在`glue`数据集中，包含非常多个NLP不同任务的数据集，config名称的不同表示下载的具体数据集也不同。
第三个参数：
split='train'，即是否要划分数据集，若设置为split='train'则返回训练集，若设置为split='test'则返回测试集。若不设置该参数，则会返回一个dict，包含dataset['train']、dataset['validation']、dataset['test']
```

返回的数据集我们可以看作是一个列表，而每一个元素是一个`dict`。如`dataset[0]`为如下形式：

```python
{'sentence1': 'Amrozi accused his brother , whom he called " the witness " , of deliberately distorting his evidence .',
 'sentence2': 'Referring to him as only " the witness " , Amrozi accused his brother of deliberately distorting his evidence .',
 'label': 1,
 'idx': 0}
```

### 数据集处理

#### tokenize化

在`NLP`中，我们接下来需要对数据集进行`tokenize`化。我们可以使用如下的函数来加载模型和`tokenizer`：

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification

model = AutoModelForSequenceClassification.from_pretrained('bert-base-uncased')
tokenizer = AutoTokenizer.from_pretraiend('bert-base-uncased')
```

上面我们加载了`bert`模型和`bert`模型对应的`tokenizer`。接下来，让我们对数据集中的每一个元素都进行`tokenize`。

首先，让我们来看看如何对其中一个元素进行`tokenize`：

```python
item = dataset[0]
item = tokenizer(item['sentence1'], item['sentence2'], truncation=True, padding='max_length', return_tensors='pt')
# padding参数设置为`max_length`表示填充到数据集中最长文本的长度
# truncation设置为True表示为大于padding长度的会截断
# return_tensors设置为pt，表示为这是个pytorch的tensor
```

在上面的函数中，`item['sentence1']`和`item['sentence2']`表示要进行`tokenize`的两个句子。这里是由于这是句子对任务匹配的数据集，因此`tokenizer`中传入了两个句子，在返回的时候会由`token_type_ids`来表明两个句子对应的`id`。正常情况下传入一个句子也是`OK`的。

例如，此处的返回值为：（仅作示例，不用细看）

```python
{'input_ids': [101, 2572, 3217, 5831, 5496, 2010, 2567, 1010, 3183, 2002, 2170, 1000, 1996, 7409, 1000, 1010, 1997, 9969, 4487, 23809, 3436, 2010, 3350, 1012, 102, 7727, 2000, 2032, 2004, 2069, 1000, 1996, 7409, 1000, 1010, 2572, 3217, 5831, 5496, 2010, 2567, 1997, 9969, 4487, 23809, 3436, 2010, 3350, 1012, 102, 0, 0...], 'token_type_ids': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,...], 'attention_mask': [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, ...]}
```

可以看到返回值为进行`tokenize`化的`dict`。但这样一个一个的处理，比较慢，而且返回值中我们看到已经丢失了原文本信息和`label`信息。

#### 批量tokenize

实际上，我们的`dataset`是我们刚刚由`load_dataset`函数加载的，该`dataset`函数拥有一个自带的`.map`方法。如下所示：

```python
def encode(item):
    return tokenizer(item['sentence1'], item['sentence2'], truncation=True, padding='max_length', return_tensors='pt')

dataset = dataset.map(encode, batched=True)
# batched设置为True的话可以使用GPU来并行化加速，大多数情况下都设置为True
```

这样做有两个好处：一是可以对`dataset`中的元素进行批量处理，二是使用`dataset.map()`方法调用的`tokenizer`方法返回的字典会添加到原字典中，而不是覆盖原字典。这样每一个字典元素除了包含`tokenize`后的信息，还包含原文本信息和`label`信息。

#### 添加标签

我们刚刚已经将数据集的每一个`dict`都添加了`token`的信息。有的时候，我们需要对每个字典都添加一个键，应该怎么做呢？

我们同样可以使用`map`方法。这里，我们用一个简单的`lambda`函数作为示例，来添加一个名为`labels`的键（原`dict`中有一个名为`label`的键）。

```python
dataset = dataset.map(lambda item: {'labels': item['label']})
```

## 调用模型

`huggingface`中可以便捷地调用预训练的模型来预测下游任务，例如可以直接使用`pipeline`函数：

```python
from transformers import pipeline

classifier = pipeline('sentiment-analysis')

result = classifier('today is a nice day!')
result = classifier(['today is a nice day', 'today is a bad day'])
```

如上所示，我们直接调用`pipeline`函数，指定了我们要完成的任务后，即可轻松执行下游任务的分类。

注意，`pipeline`函数可以指定`model`和`tokenizer`。若不指定，将会调用该任务中常用的通用模型。

## 加载模型

与上一节中直接调用`pipeline`不同，我们也可以仅仅加载模型来进行`fine-tune`，或者将其直接应用为一个传统的`torch`模型。

流程如下所示：

```python
from transformers import AutoConfig, AutoTokenizer, AutoModelForSequenceClassification, AutoModel

model_name = "nlptown/bert-base-multilingual-uncased-sentiment"
config = AutoConfig.from_pretrained(model_name)
## 对config做想要的修改，此处略 ##
model = AutoModel.from_config(config)
tokenizer = AutoTokenizer.from_pretrained(model_name)
```

这之后，我们便可以使用模型：

```python
text = 'test sentence'
my_input = tokenizer(text, padding=True, max_length=128, truncation=True, return_tensors='pt')
output = model(**my_input)
```



