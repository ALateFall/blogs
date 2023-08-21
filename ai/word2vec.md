---
layout: post
title: word2vec入门指北
category: ai
date: 2023-8-19
---
word2vec的API变化太大，本文以2023年7月的word2vec最新版本进行记录。
<!-- more -->
[toc]

# Word2Vec in Gensim

本文站在代码的角度对`word2vec`进行基本讲解，原理部分请自行`STFW`。

由于众所周知的原因，`gensim`库的`word2vec`随着版本的变动，各种`API`一天一个样，于是便有了此文（`2023年`）。

## 训练

实际上，`word2vec`可以在自己的语料库上训练（比如就是要进行词嵌入的数据集），也可以在大型的各种`wiki`语料库中训练。

### 自己的语料库

对于自己的语料库，我们需要将其进行数据清洗、分词、删除停用词，再交给`word2vec`来进行训练。

对于分词，一般我们使用`jieba`库，改天我会写一个`jieba`库的常用功能放在这里。

对于数据清洗，一般可以使用如下代码：

```python
def clean_text(text):
    string = re.sub(u"[，。 :,.；|-“”——_/nbsp+&;@、《》～（）())#O！：【】]", "", text)
    return string.strip().lower()
```

随后，我们只需要定义`word2vec`的相关设置即可开始训练。

首先明确一点：`word2vec`接受的语料库是一个嵌套列表。外面的一层列表中，每一个列表表示一个句子，而内部的一层列表是由这个句子分词组成的。

例如：

```python
[['震惊','转发','求证','想','不敢','想','美国','一桶','金龙鱼','食用','用油','食用油','元','人民','人民币','一桶','食用','油','食用油','相当','当于','相当于','中国','超市','40','多元','现在','估计','已经','涨','五六','六十','十元','五六十','六十元','五六十元','金龙鱼','纽约','沃尔玛','感恩','感恩节','时','16','美元','圣诞','圣诞节','降至','13','美元','折合','人民人民币','858','元','油是','绿色','天然','纯天然','基因','转基因','中国','一桶','食用','用油','食用油','卖','几十','百元'],
 ['法院','底线','湖南','长沙','一位','朋友','小朋友','上学','路上','捡','万元','原地','不动','原地不动','失主','冒领','不知','知情','不知情','孩子','学校','告知','老师','表扬','好人','好事','好人好事','很快','传开','真','失主','听说','上门','找上门','要钱','未果','竟然','孩子','告上','法庭','法院','判决','孩子','家长','赔偿','6000','元气','家长','大骂','孩子','手','贱','捡','钱','y','瀟湘','墨人','千里']]
```

随后，`word2vec`以以下方式训练：

```python
from gensim.models import word2vec

model = word2vec.Word2Vec(
	corpus, # 语料库，就是上面提到的嵌套列表
    min_count=min_count, # 少于min_count的词语不会参与训练，想都训练就填1
    vector_size=vector_size, # 一个词语转换为向量的维度
    workers=workers, # 线程数量，可以填为CPU核数量
    epochs=epochs, # 训练迭代多少次
    window=window_size, # 要看周围的多少个词语
    batch_words=batch_words, # 每一轮训练给多少个词语
    sg=0 # CBOW为0，Skip-Gram为1.CBOW更快但效果没有Skip-Gram好
)
```

### Wiki语料库

使用`wiki`的语料库可能会效果更好，但是很可能会存在一个问题：放到自己的语料库的时候，有的词语不存在。

首先，下载`wiki`的语料库，在[这里](https://dumps.wikimedia.org/zhwiki/)。

下载完成后，用如下方式加载：

```python
from gensim.corpora import WikiCorpus

# 下一行的第一个参数是下载的文件名，第二个留空即可
wiki_corpus = WikiCorpus('zhwiki-20230701-pages-articles-multistream.xml.bz2', dictionary={})
```

接下来，我们可以使用`get_texts`函数来从里面提取出文本并一行一行地保存：

```python
if not os.path.exists('/workspace/ltfallcode/datasets_weibo/wiki_text.txt'):
    with open('wiki_text.txt', 'w', encoding='utf-8') as f:
        for text in wiki_corpus.get_texts():
            f.write(' '.join(text) + '\n')
            text_num += 1
            if text_num % 10000 == 0:
                print('{} articles processed.'.format(text_num))

        print('Done with {} articles processed.'.format(text_num))
```

将每一行进行分词后保存到文件：

```python
if not os.path.exists('/workspace/ltfallcode/datasets_weibo/wiki_text_seg.txt'):
    with open('wiki_text_seg.txt', 'w', encoding='utf-8') as new_f:
        with open('/workspace/ltfallcode/datasets_weibo/wiki_text.txt') as f:
            for times, data in enumerate(f, 1):
                if times % 1000 == 0:
                    print('data num:', times)
                data = jieba.cut_for_search(data)
                data = [word for word in data if word!= ' ']
                data = ' '.join(data)

                new_f.write(data)
```

如此以来，可以直接使用`LineSentence`函数来从一个每一行都进行了分词的文件中获得语料库：

```python
train_data = word2vec.LineSentence('./wiki_text_seg.txt')
```

训练即可：

```python
seed = 666
sg = 0
window_size = 10
vector_size = 100
min_count = 1
workers = 8
epochs = 5
batch_words = 10000

model = word2vec.Word2Vec(
    train_data,
    min_count=min_count,
    vector_size=vector_size,
    workers=workers,
    epochs=epochs,
    window=window_size,
    batch_words=batch_words
)
```

## 模型使用

### 获得某个词语对应的词向量

```python
vector = model.wv['词语']
```

![image-20230718105520745](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307181055855.png)

### 获得某个词语最相近的词语

```python
model.wv.most_similar('电脑')
```

![image-20230718110006358](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307181100388.png)

### 遍历所有语料库中出现过的词语

```python
for word in model.wv.index_to_key:
    print(word)
```

### 处理未出现的词语

上文中我们提到，比如我们在大型语料库中训练后将其使用到我们自己的数据集上，可能会出现有的词语没有的问题，这个时候就需要处理未出现的词语。

有两种方法：

- 未知词语向量使用全零向量
- 未知词语向量使用平均向量

例如全零向量，我们可以使用错误处理来简便地将其使用全零向量代替：

```python
words = ['哈哈', '电脑', '1']

for word in words:
    try:
        vector = model.wv[word]
    except KeyError as e:
        vector = np.zeros(model.vector_size)
    print(vector)
```

![image-20230718112418690](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307181124730.png)