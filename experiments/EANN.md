[toc]

# EANN复现笔记

## 梯度翻转层的实现

我们写的继承于`nn.Module`的是`Module`的子类，它只需要实现`forward`方法。若我们实现梯度翻转，那么需要定义一个继承于`torch.autograd.Function`类的子类，它来实现`forward`方法和`backward`方法，并最终在继承于`nn.Module`子类的`forward`方法中来使用`.apply`函数进行调用。

```python
class ReverseFunction(torch.autograd.Function):
    @staticmethod
    def forward(self, x):
        setting = Settings()
        self.alpha = setting.lambd # 不会调用init方法
        return x.view_as(x)

    @staticmethod
    def backward(self, grad_output):
        return -1 * self.alpha * grad_output
    

class ReverseLayer(nn.Module):
    def __init__(self):
        super(self, ReverseLayer).__init__()
    
    def forward(self, x):
        return ReverseFunction.apply(x)
```

也可以不需要`ReverseLayer`而写成函数式的写法，但如你所见，仍然需要重写继承于`torch.autograd.Function`类的方法：

```python
class ReverseFunction(torch.autograd.Function):
    @staticmethod
    def forward(self, x):
        setting = Settings()
        self.alpha = setting.lambd
        return x.view_as(x)

    @staticmethod
    def backward(self, grad_output):
        return -1 * self.alpha * grad_output
    
def grad_reverse(x):
    return ReverseLayerF()(x)
```

