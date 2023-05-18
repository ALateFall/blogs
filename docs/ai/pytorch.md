[toc]

# pytorch基本使用

## about

> Talk is cheap, show me the code.
>

## some functions

- squeeze(tensor, dim)

> 去掉一维。接受第一个参数是要去掉的tensor，第二个参数是要去掉的维度。
>
> unsqueeze反之，是加上一维。

- np.newaxis

```python
np_a = np.array([1, 2, 3])
assert(np_a.shape==(3,))

np_b = np_a[np.newaxis, :]
assert(np_b.shape==(1, 3))
```



## 搭建模型

两种方式：

### 方法1

```python
class Net(torch.nn.Module):
    def __init__(self, n_feature, n_hidden, n_output):
        super(Net, self).__init__()
        self.hidden = torch.nn.Linear(n_feature, n_hidden)
        self.predict = torch.nn.Linear(n_hidden, 1)
    
    def forward(self, x):
        x = torch.relu(self.hidden(x))
        x = self.predict(x)
        return x
```

### 方法2

```python
net = torch.nn.Sequential(
    torch.nn.Linear(2, 10),
    torch.nn.ReLU(),
    torch.nn.Linear(10, 2)
)
print(net)
```



## 训练

```python
optimizer = torch.optim.SGD(net.parameters(), lr=0.5)
loss_func = torch.nn.MSELoss()
```

```python
for t in range(100):
    prediction = net(x)
    
    loss = loss_func(prediction, y)
    
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
```

## 保存及加载模型

### 方法1

```python
# 保存
torch.save(net, 'net.pkl')

# 加载
net2 = torch.load('net.pkl')
```

### 方法2

```python
# 保存
torch.save(net, 'net_params.pkl')

# 加载:需自己定义好保存的网络
net3 = torch.nn.Sequential(
	torch.nn.Linear(1, 10),
    torch.nn.ReLU(),
    torch.nn.Linear(10, 1)
)
net3.load_state_dict(torch.load('net_params.pkl'))
```

## 加载数据集

```python
import torch.utils.data as Data

BATCH_SIZE = 5

x = torch.linspace(1, 10, 10)
y = torch.linspace(10, 1, 10)
torch_dataset = Data.TensorDataset(x, y)

loader = Data.DataLoader(
    dataset = torch_dataset,
    batch_size = BATCH_SIZE,  # 每一个batch size
    shuffle = True,  # 是否打乱
    num_workers = 2,  # 线程个数
)


def show_batch():
    for epoch in range(3):  # 训练三次
        for step, (batch_x, batch_y) in enumerate(loader):  # 每一步
            print('Epoch: ', epoch, '| Step:', step, '|batch x:',
                 batch_x.numpy(), '|batch y:', batch_y.numpy())
            
show_batch()
            
```

## 优化器

```python
LR = 0.5
opt_SGD         = torch.optim.SGD(net.parameters(), lr=LR)
opt_Momentum    = torch.optim.SGD(net.parameters(), lr=LR, momentum=0.8)
opt_RMSprop     = torch.optim.RMSprop(net.parameters(), lr=LR, alpha=0.9)
opt_Adam        = torch.optim.Adam(net.parameters(), lr=LR, betas=(0.9, 0.99))
```



## CNN

```python
import torch
import torch.nn as nn
import torch.utils.data as Data
import torchvision
import matplotlib.pyplot as plt
```

```python
EPOCH = 1
BATCH_SIZE = 50
LR = 0.001
DOWNLOAD_MNIST = True
```

```python
train_data = torchvision.datasets.MNIST(
    root='.',  # 下载目录
    train=True,  # 这里填True的话，返回训练集，填False返回测试集。
    transform=torchvision.transforms.ToTensor(),  # 改变数据形式，这里改成tensor，并且transforms会从0-255压缩到0-1
    download=DOWNLOAD_MNIST  # 下载了就填False
)
```

```python
plt.imshow(train_data.data[0].numpy(), cmap='gray')
plt.title('%i' % train_data.targets[0])
plt.show()
```

```python
train_loader = Data.DataLoader(dataset=train_data, batch_size=BATCH_SIZE, shuffle=True)
```

```python
test_data = torchvision.datasets.MNIST(root='.', train=False) # 对照上面
test_x = torch.unsqueeze(test_data.data, dim=1).type(torch.FloatTensor)[:2000]/255.
test_y = test_data.targets[:2000]
```

```python
class CNN(nn.Module):
    def __init__(self):
        super(CNN, self).__init__()
        self.conv1 = nn.Sequential(
            nn.Conv2d(
                in_channels=1,
                out_channels=16,
                kernel_size=5,
                stride=1, 
                padding=2,
            ),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2),
        )
        self.conv2 = nn.Sequential(
            nn.Conv2d(16, 32, 5, 1, 2),
            nn.ReLU(),
            nn.MaxPool2d(2)
        )
        self.out = nn.Linear(32 * 7 * 7, 10)
        
        
    def forward(self, x):
        x = self.conv1(x)
        x = self.conv2(x)
        x = x.view(x.size(0), -1) # 展平，如这里是(batch, 32, 7, 7) -> (batch, 32*7*7)
        output = self.out(x)
        return output
```

```python
cnn = CNN()
print(cnn)

optimizer = torch.optim.Adam(cnn.parameters(), lr=LR)
loss_func = nn.CrossEntropyLoss()

for epoch in range(EPOCH):
    for step, (x, y) in enumerate(train_loader):
        output = cnn(x)
        loss = loss_func(output, y)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        if step % 50 == 0:
            test_output = cnn(test_x)
            pred_y = torch.max(test_output, 1)[1].data.numpy() # max函数的第二个参数是维度，返回值第一个是值，返回值第二个是下标
            accuracy = float((pred_y == test_y.data.numpy()).astype(int).sum()) / float(test_y.size(0))
            print('Epoch: ', epoch, '| train loss: %.4f' % loss.data.numpy(), '| test accuracy: %.2f' % accuracy)
```

```python
test_output = cnn(test_x)
print(torch.max(test_output, 1)[1])
```

## RNN classification(Implemented by LSTM)

```python
import torch
from torch import nn
import torchvision.datasets as dsets
import torchvision.transforms as transforms
import matplotlib.pyplot as plt

EPOCH = 1
BATCH_SIZE = 64
TIME_STEP = 28
INPUT_SIZE = 28
LR = 0.01
DOWNLOAD_MNIST = True
```

```python
train_data = dsets.MNIST(root='.', train=True, transform=transforms.ToTensor(), download=True)
train_loader = torch.utils.data.DataLoader(dataset=train_data, batch_size=BATCH_SIZE, shuffle=True)


test_data = dsets.MNIST(root='.', train=False, transform=transforms.ToTensor())
test_x = test_data.data.type(torch.FloatTensor)[:2000]/255
test_y = test_data.targets.numpy()[:2000]
```

```python
class RNN(nn.Module):
    def __init__(self):
        super(RNN, self).__init__()
        
        self.rnn = nn.LSTM(
            input_size=INPUT_SIZE,
            hidden_size=64,
            num_layers=1,
            batch_first=True, # 也就是数据维度：(batch, timestep, input)
        )
        self.out = nn.Linear(64, 10)
        
    def forward(self, x):
        r_out, (h_n, h_c) = self.rnn(x, None)
        out = self.out(r_out[:, -1, :])
        return out
    
rnn = RNN()
print(rnn)
```

```python
optimizer = torch.optim.Adam(rnn.parameters(), lr=LR)
loss_func = nn.CrossEntropyLoss()

for epoch in range(EPOCH):
    for step, (x, y) in enumerate(train_loader):
        x = x.view(-1, 28, 28)
        output = rnn(x)
        loss = loss_func(output, y)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        if step % 50 == 0:
            test_output = rnn(test_x)
            pred_y = torch.max(test_output, 1)[1].data.numpy()
            accuracy = (pred_y == test_y).astype(int).sum() / test_y.size
            print('EPOCH:', epoch, '| train loss : %.4f' % loss.data.numpy(), '| test accuracy',  accuracy)
```

```python
test_output = rnn(test_x[:10].view(-1, 28, 28))
pred_y = torch.max(test_output, 1)[1].data.numpy()
print(pred_y, 'prediction number')
print(test_y[:10], 'real number')
```

## RNN regression

```python
import torch
from torch import nn
import torchvision.datasets as dsets
import torchvision.transforms as transforms
import matplotlib.pyplot as plt
import numpy as np


TIME_STEP = 10
INPUT_SIZE = 1
LR = 0.02

class RNN(nn.Module):
    def __init__(self):
        super(RNN, self).__init__()
        self.rnn = nn.RNN(
            input_size=INPUT_SIZE,
            hidden_size=32,
            num_layers=1,
            batch_first=True,
        )
        self.out = nn.Linear(32, 1)
    
    
    def forward(self, x, h_state):
        # x (batch, time_step, input_size)
        # h_state (n_layers, batch, hidden_size)
        # r_out (batch, time_step, output_size)
        r_out, h_state = self.rnn(x, h_state)
        
        outs = []
        for time_step in range(r_out.size(1)):
            outs.append(self.out(r_out[:, time_step, :]))
        return torch.stack(outs, dim=1), h_state
```

```python
rnn = RNN()
print(rnn)
```

```python
optimizer = torch.optim.Adam(rnn.parameters(), lr=LR)
loss_func = nn.MSELoss()

h_state = None

for step in range(100):
    start, end = step * np.pi, (step+1)*np.pi
    steps = np.linspace(start, end, TIME_STEP, dtype=np.float32, endpoint=False)
    x_np = np.sin(steps)
    y_np = np.cos(steps)
    
    x = torch.from_numpy(x_np[np.newaxis, :, np.newaxis])
    y = torch.from_numpy(y_np[np.newaxis, :, np.newaxis])
    
    prediction, h_state = rnn(x, h_state)
    h_state = h_state.data  # 重新打包隐藏状态，断开上次迭代连接。
    
    loss = loss_func(prediction, y)
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    
    plt.plot(steps, y_np.flatten(), 'r-')
    plt.plot(steps, prediction.data.numpy().flatten(), 'b-')
    plt.draw(); plt.pause(0.05)

plt.ioff()
plt.show()
```

