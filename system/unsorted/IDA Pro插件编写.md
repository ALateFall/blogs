---
layout: post
title: 从零开始的 IDA pro 插件编写
category: unsorted
date: 2025-07-01 12:00:00
---


所以IDA的一键漏洞挖掘的插件在哪里下？
<!-- more -->



# IDA Pro插件编写

本篇文章基于`IDA Pro9.0`编写。

本文的大致脉络为：先让读者能够快速编写出能够在`IDA`中显示的按钮，也就是`UI`部分：），随后笔者会给出扩充功能的方法，以及一些常见的`API`。

现阶段`IDA Pro`的插件有三种方法可以编写，即`C++ SDK`、`IDAPython`、`IDC`。其区别用`AI`分析大致如下：

| 特性            | `C++ SDK`                            | `IDAPython`                           | `IDC`                  |
| :-------------- | :----------------------------------- | :------------------------------------ | :--------------------- |
| **性能**        | 最高 (编译型)                        | 中等 (解释型，但可调用本地代码)       | 较低 (解释型)          |
| **开发速度**    | 慢 (需要编译、调试周期长)            | 快 (解释型，即写即运行)               | 非常快 (用于简单任务)  |
| **学习曲线**    | 陡峭 (需要 `C++` 和 `IDA` 内部知识)  | 平缓 (需要 `Python` 基础)             | 非常平缓               |
| **API 访问**    | 最全面 (可访问所有核心功能)          | 非常全面 (绝大多数功能已封装)         | 受限                   |
| **库支持**      | 标准 `C++` 库和第三方库              | 极其丰富 (Python 生态系统)            | 几乎没有               |
| **跨平台/版本** | 需要为不同平台和 IDA 版本重新编译    | 脚本通常可跨平台，对版本有一定兼容性  | 兼容性最好             |
| **UI 开发**     | 强大 (可使用 `Qt` 或原生 `WinAPI`)   | 强大 (通过 `PyQt`/`PySide` 使用 `Qt`) | 非常有限               |
| **主要用途**    | 核心功能扩展、高性能分析器、商业插件 | 快速原型、数据分析、日常任务自动化    | 简单、一次性的脚本命令 |

可以看到 `IDAPython` 是一个不错的选项，它在**开发难度和功能丰富度上有着不错的平衡**，在大多数不严格要求性能的场景下都能很好地适用。因此本篇文章会基于`IDAPython`来编写。

你可以将`IDApython`理解为原生的`python`，没有奇怪的语法，只有各种`api`。因此只需要编写一个`.py`文件，放到`IDA Pro`的`plugins`目录下即可。

## 0x00. 基本框架

一个基本的框架如下所示，各个部分都是必须存在的，根据注释替换即可：

```python
import ida_idaapi # 框架的核心定义
import ida_kernwin # 和IDA界面交互的功能，例如打印消息

# 注册插件，需要继承于ida_idaapi.plugin_t
class VulnHunter(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_UNL # 定义插件的生命周期，设置为PLUGIN_UNL会让调用插件后立即卸载
    comment = "漏洞挖掘的好帮手" # 插件的描述
    wanted_name = "VulnHunter" # 在edit-plugins中显示的名称
    wanted_hotkey = "Shift-V" # 快捷键，例如我们这里使用Shift-v
    help = ""
    
    def init(self):
        ida_kernwin.msg("VulnHunter: Plugin registered Successfully.\n")
        return VulnHunter_Runner() # 当前class是加载器，这里返回它的执行器

# 执行器
class VulnHunter_Runner(ida_idaapi.plugmod_t):
    # 用户触发插件时，会触发该功能
    def run(self, arg):
        ida_kernwin.msg("VulnHunter: Exec Func\n")

# ida扫描到该函数的时候，才会认为这是一个插件，因此必须存在，且返回加载器
def PLUGIN_ENTRY():
    return VulnHunter()
```

完成后，我们就可以在IDA中使用这个插件。现在它有基本的功能：

- 在`Edit-Plugin`中加载并调用该插件
- 使用快捷键`Shift+V`调用该插件

## 0x01. 插件的“动作机制”

这个动作机制实际上是笔者取的名字。在我们使用第一步编写插件的功能时，它很明显**只适合单步处理**的功能。很简单，因为它只有一个按钮，我们点击这个按钮，执行一些功能，然后这个功能就执行完毕了。

而实际上我们会有一些别的需求，例如说在实际场景中，我们可能需要让插件**拥有二级菜单**，或者说我们希望在`IDA`的代码窗口中通过**鼠标右键**来唤起一些功能。

那这里我们就可以用到“动作机制”。我们可以将一个功能视为一个动作，随后我们在插件中定义一个二级菜单，它下面包含多个功能，每一个功能就是一个动作。这样一来可以实现一定程度上的模块化。

### 在二级菜单添加功能

首先，我们可以编写好各个功能模块（也就是动作）。为了作为演示，这里的功能模块都是空的。

作为例子，这里我们编写了两个空的功能模块，如果需要添加功能，只需要在代码中添加即可：

```python
class ScanAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_kernwin.msg("VulnHunter: Scanning for vulnerabilities...\n")
        # 在这里编写代码
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ConfigAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_kernwin.msg("VulnHunter: Opening configuration dialog...\n")
        # 在这里编写代码
        ida_kernwin.warning("Configuration feature is not implemented yet.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
```

其中，不难注意到我们需要手动实现`activate`方法和`update`方法。他们的作用分别如下：

- `activate`方法：用户执行该动作时会调用该函数。随后，返回值为`1`表示修改了数据库。
- `update`方法：表示该按钮**是否可用**。可以根据`ctx`，来设置`update`的返回值。其中我们使用`ida_kernwin.AST_ENABLE_FOR_WIDGET`表示该按钮可用；使用`ida_kernwin.AST_DISABLE_FOR_WIDGET`表示该按钮不可用。在上面我们编写的例子中，我们使用了`enable_always`，表示该功能始终是可用的状态。**注意`update`方法会频繁被`IDA`调用，因此最好里面不要添加耗时的功能**。

随后，我们需要注册这些动作，并将他们放到二级菜单中。

因此，我们回到加载器的`init`函数中，先定义动作：

```python
# 定义一些动作，例如，这里我们定义在IDA Pro右键菜单的两个动作
self.actions = [
    ida_kernwin.action_desc_t(
        name="vulnHunter::scanAction",             # 该动作的内部名称，注册动作的时候需要用到
        label='Scan for Vulnerabilities',          # 菜单上显示的文本
        handler=ScanAction(),                      # 处理该动作的类的实例
        shorcut='Shift-V',                         # 快捷键
        tooltip='Scan Vulns',                      # 鼠标悬停时显示的文本
        icon=139                                   # IDA内置图标的编号，139是放大镜：）
    ),
    ida_kernwin.action_desc_t(
        'vulnHunter::config',
        'config for vulnHunter',
        ConfigAction(),
        'Shift+B',
        '配置设置',
        139
    )
]
```

随后，注册这些动作：

```python
for action in self.actions:
    if not ida_kernwin.register_action(action):
        ida_kernwin.msg(f"VulnHunter Plugin: Failed to register action {action.name}. \n")
    ida_kernwin.msg(f"Action {action.name} register successfully.\n")
```

将它们添加到二级菜单：

```python
# 定义菜单路径
menu_path = 'Edit/VulnHunter/' # 注意没有最后这个/还不行..

# 将上述动作绑定到菜单下
for action in self.actions:
    ida_kernwin.attach_action_to_menu(
        menupath=menu_path,
        name=action.name,
        flags=ida_kernwin.SETMENU_APP
    )
```

因此，之前的插件可以修改为如下代码，现在他将在`IDA`的`edit`目录下拥有一个二级菜单，里面有两个功能：

```python
import ida_idaapi # type: ignore # 框架的核心定义
import ida_kernwin # type: ignore # 和IDA界面交互的功能，例如打印消息

# -------------------------------------------------------------
#                     IDA 插件主程序部分
# -------------------------------------------------------------

# 注册插件，需要继承于ida_idaapi.plugin_t
class VulnHunter(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP      # 定义插件的生命周期，设置为PLUGIN_UNL会让调用插件后立即卸载，PLUGIN_KEEP可以让其一直保存在内存中，等等
    comment = "漏洞挖掘的好帮手"          # 插件的描述
    wanted_name = "VulnHunter"          # 在edit-plugins中显示的名称
    wanted_hotkey = "Shift-V"           # 快捷键，例如我们这里使用Shift-v
    help = ""
    
    def init(self):
        ida_kernwin.msg("VulnHunter: Plugin registered Successfully.\n")

        # 定义一些动作，例如，这里我们定义在IDA Pro右键菜单的两个动作
        self.actions = [
            ida_kernwin.action_desc_t( # 这个可以简单定义一个动作，即ida_kernwin.action_desc_t
                name="vulnHunter::scanAction",             # 该动作的内部名称，注册动作的时候需要用到
                label='Scan for Vulnerabilities',          # 菜单上显示的文本
                handler=ScanAction(),                      # 处理该动作的类的实例
                shorcut='Shift-V',                         # 快捷键
                tooltip='Scan Vulns',                      # 鼠标悬停时显示的文本
                icon=139                                   # IDA内置图标的编号，139是放大镜：）
            ),
            ida_kernwin.action_desc_t(
                'vulnHunter::config',
                'config for vulnHunter',
                ConfigAction(),
                'Shift+B',
                '配置设置',
                139
            )
        ]
        
        # 注册我们上面列表的所有动作
        for action in self.actions:
            if not ida_kernwin.register_action(action):
                ida_kernwin.msg(f"VulnHunter Plugin: Failed to register action {action.name}. \n")
            ida_kernwin.msg(f"Action {action.name} register successfully.\n")
        
        
        # 定义菜单路径
        menu_path = 'Edit/VulnHunter/' # 注意没有最后这个/还不行..
        
        # 将上述动作绑定到菜单下
        for action in self.actions:
            ida_kernwin.attach_action_to_menu(
                menupath=menu_path,
                name=action.name,
                flags=ida_kernwin.SETMENU_APP
            )
        
        ida_kernwin.msg("VulnHunter Plugin: Initialized Successfully.\n")
        
        return ida_idaapi.PLUGIN_KEEP

# 执行器
class VulnHunter_Runner(ida_idaapi.plugmod_t):
    # 用户触发插件时，会触发该功能
    def run(self, arg):
        ida_kernwin.msg("VulnHunter: Exec Func\n")

# ida扫描到该函数的时候，才会认为这是一个插件，因此必须存在，且返回加载器
def PLUGIN_ENTRY():
    return VulnHunter()

# -------------------------------------------------------------
#                     IDA 插件 动作部分
# -------------------------------------------------------------

# --------------------------------------------------------------------------
# 动作1: 扫描漏洞的处理程序
# --------------------------------------------------------------------------
class ScanAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_kernwin.msg("VulnHunter: Scanning for vulnerabilities...\n")
        # 在这里放置你的漏洞扫描核心代码
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# --------------------------------------------------------------------------
# 动作2: 插件配置的处理程序
# --------------------------------------------------------------------------
class ConfigAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_kernwin.msg("VulnHunter: Opening configuration dialog...\n")
        # 在这里放置打开配置窗口或执行配置逻辑的代码
        ida_kernwin.warning("Configuration feature is not implemented yet.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
```

如下所示：

<img src="https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20250823173257300.png" alt="image-20250823173257300" style="zoom:50%;" />

## 0x02. 插件的 UI Hook

在上一部分中我们介绍了在二级菜单添加功能，但这些都属于`IDA`上方工具栏中的功能。如果我们需要在别的地方添加功能，例如说在反编译的代码中的鼠标右键想唤起功能时，就需要对`UI`进行`hook`。

我们接下来以鼠标右键添加两个功能为例子，在反编译的代码中以及汇编代码中，可以鼠标右键代码，并唤起二级菜单中的两个功能。

### 在鼠标右键添加功能

我们先同样定义好两个动作。在这个例子中，我们将`action_name`之类的属性写在了动作的类中。

此外，我们上面提到，动作的类中`update`方法决定其是否被显示，因此我们会编写`update`方法判断其窗口，如果窗口类型是反编译窗口和汇编窗口，则会显示，除此之外则不会显示：

```python
# 注意在这个例子中，我将动作的name和label等放到了类中
class VulnHunterAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = "vulnHunter:action1"
        self.action_label = "VulnHunter: The action1"
        self.action_shortcut = "Shift-1"
    
    def activate(self, ctx):
        current_address = ctx.cur_ea
        ida_kernwin.msg(f"VulnHunter: Executed at address 0x{current_address:x}")
        ida_kernwin.info(f"VulnHunter scan started at 0x{current_address:x}")
        return 1
    
    def update(self, ctx):
        """
        我们判断窗口类型，如果其位于反编译窗口和汇编窗口，右键才会使其显示！：）
        """
        widget_type = ctx.widget_type
        
        if widget_type == ida_kernwin.BWN_DISASM or widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # 如果是汇编窗口 或者是 反编译窗口
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
class VulnHunterAction2(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = "vulnHunter:action2"
        self.action_label = "VulnHunter: The action2"
        self.action_shortcut = "Shift-2"
    
    def activate(self, ctx):
        current_address = ctx.cur_ea
        ida_kernwin.msg(f"VulnHunter: Executed at address 0x{current_address:x}\n")
        ida_kernwin.info(f"VulnHunter scan started at 0x{current_address:x}\n")
        return 1
    
    def update(self, ctx):
        """
        我们判断窗口类型，如果其位于反编译窗口和汇编窗口，右键才会使其显示！：）
        """
        widget_type = ctx.widget_type
        
        if widget_type == ida_kernwin.BWN_DISASM or widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # 如果是汇编窗口 或者是 反编译窗口
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
```

随后，我们就可以编写`UI Hook`的部分，它继承于`ida_kernwin.UI_Hooks`类。其中我们可以定义多种显示的地方，这里我们希望在鼠标右键时显示，因此我们可以实现其`finish_populating_widget_popup`方法，如此在鼠标右键菜单生成时，就会触发这个`hook`。在代码中，我们添加刚刚定义的几个动作，注意使用的是动作的内部名称：

```python
class RightMouseHook(ida_kernwin.UI_Hooks):
    
    # 这个函数就是在右键菜单生成结束的时候调用的：）
    def finish_populating_widget_popup(self, widget, popup_handle):
        """
        右键菜单弹出时，附加几个动作
        widget表示窗口
        popup_handle表示正在被构建的右键菜单本身
        """
        action_names = [
            "vulnHunter:action1",
            "vulnHunter:action2"
        ]
        
        for action_name in action_names:
            ida_kernwin.attach_action_to_popup(
                widget=widget,                  # 当前窗口
                popup_handle=popup_handle,      # 当前右键菜单
                name=action_name,               # 附加所有注册的动作名称
                popuppath='VulnHunter/'         # 位于右键菜单的VulnHunter/下 
            )
```

最后，我们仍然在插件加载器的`init`方法中，注册我们的动作：

```python
# 注册动作
action1 = VulnHunterAction()
action2 = VulnHunterAction2()

self.actions = [
    ida_kernwin.action_desc_t(
        name=action1.action_name,
        label=action1.action_label,
        handler=action1,
        shortcut=action1.action_shortcut,
        tooltip='action1 text',
        icon=139
    ),
    ida_kernwin.action_desc_t(
        name=action2.action_name,
        label=action2.action_label,
        handler=action2,
        shortcut=action2.action_shortcut,
        tooltip='action2 text',
        icon=139
    )
]

for action in self.actions:
    if not ida_kernwin.register_action(action):
        ida_kernwin.msg(f"VulnHunter: plugin function {action.action_name} register failed.\n")
```

并安装好我们编写的`UI Hook`：

```python
# 实例化并安装UI的钩子，如此一来在右键时就会显示我们的功能
self.ui_hooks = RightMouseHook()
if not self.ui_hooks.hook(): # 安装钩子
    ida_kernwin.msg("VulnHunter: The UI Hook install failed. You may not see the functions in the right mouse button.\n")
```

此时，完整代码如下：

```python
import ida_idaapi # type: ignore # 框架的核心定义
import ida_kernwin # type: ignore # 和IDA界面交互的功能，例如打印消息

# -------------------------------------------------------------
#                     IDA 插件主程序部分
# -------------------------------------------------------------

# 注册插件，需要继承于ida_idaapi.plugin_t
class VulnHunter(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP      # 定义插件的生命周期，设置为PLUGIN_UNL会让调用插件后立即卸载，PLUGIN_KEEP可以让其一直保存在内存中，等等
    comment = "漏洞挖掘的好帮手"          # 插件的描述
    wanted_name = "VulnHunter"          # 在edit-plugins中显示的名称
    wanted_hotkey = "Shift-V"           # 快捷键，例如我们这里使用Shift-v
    help = ""
    
    def init(self):
        ida_kernwin.msg("VulnHunter: Plugin registered Successfully.\n")
        
        # 注册动作
        action1 = VulnHunterAction()
        action2 = VulnHunterAction2()
        
        self.actions = [
            ida_kernwin.action_desc_t(
                name=action1.action_name,
                label=action1.action_label,
                handler=action1,
                shortcut=action1.action_shortcut,
                tooltip='action1 text',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name=action2.action_name,
                label=action2.action_label,
                handler=action2,
                shortcut=action2.action_shortcut,
                tooltip='action2 text',
                icon=139
            )
        ]
        
        for action in self.actions:
            if not ida_kernwin.register_action(action):
                ida_kernwin.msg(f"VulnHunter: plugin function {action.action_name} register failed.\n")
        
        # 实例化并安装UI的钩子，如此一来在右键时就会显示我们的功能
        self.ui_hooks = RightMouseHook()
        if not self.ui_hooks.hook(): # 安装钩子
            ida_kernwin.msg("VulnHunter: The UI Hook install failed. You may not see the functions in the right mouse button.\n")
        
        return ida_idaapi.PLUGIN_KEEP

# 执行器
class VulnHunter_Runner(ida_idaapi.plugmod_t):
    # 用户触发插件时，会触发该功能
    def run(self, arg):
        ida_kernwin.msg("VulnHunter: Exec Func\n")
        
        
# -------------------------------------------------------------
#                     动作部分
# -------------------------------------------------------------

# 注意在这个例子中，我将动作的name和label等放到了类中
class VulnHunterAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = "vulnHunter:action1"
        self.action_label = "VulnHunter: The action1"
        self.action_shortcut = "Shift-1"
    
    def activate(self, ctx):
        current_address = ctx.cur_ea
        ida_kernwin.msg(f"VulnHunter: Executed at address 0x{current_address:x}")
        ida_kernwin.info(f"VulnHunter scan started at 0x{current_address:x}")
        return 1
    
    def update(self, ctx):
        """
        我们判断窗口类型，如果其位于反编译窗口和汇编窗口，右键才会使其显示！：）
        """
        widget_type = ctx.widget_type
        
        if widget_type == ida_kernwin.BWN_DISASM or widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # 如果是汇编窗口 或者是 反编译窗口
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
class VulnHunterAction2(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = "vulnHunter:action2"
        self.action_label = "VulnHunter: The action2"
        self.action_shortcut = "Shift-2"
    
    def activate(self, ctx):
        current_address = ctx.cur_ea
        ida_kernwin.msg(f"VulnHunter: Executed at address 0x{current_address:x}\n")
        ida_kernwin.info(f"VulnHunter scan started at 0x{current_address:x}\n")
        return 1
    
    def update(self, ctx):
        """
        我们判断窗口类型，如果其位于反编译窗口和汇编窗口，右键才会使其显示！：）
        """
        widget_type = ctx.widget_type
        
        if widget_type == ida_kernwin.BWN_DISASM or widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # 如果是汇编窗口 或者是 反编译窗口
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

# -------------------------------------------------------------
#                     UI 钩子
# -------------------------------------------------------------
        
class RightMouseHook(ida_kernwin.UI_Hooks):
    
    # 这个函数就是在右键菜单生成结束的时候调用的：）
    def finish_populating_widget_popup(self, widget, popup_handle):
        """
        右键菜单弹出时，附加几个动作
        widget表示窗口
        popup_handle表示正在被构建的右键菜单本身
        """
        action_names = [
            "vulnHunter:action1",
            "vulnHunter:action2"
        ]
        
        for action_name in action_names:
            ida_kernwin.attach_action_to_popup(
                widget=widget,                  # 当前窗口
                popup_handle=popup_handle,      # 当前右键菜单
                name=action_name,               # 附加所有注册的动作名称
                popuppath='VulnHunter/'         # 位于右键菜单的VulnHunter/下 
            )

# ida扫描到该函数的时候，才会认为这是一个插件，因此必须存在，且返回加载器
def PLUGIN_ENTRY():
    return VulnHunter()
```

如此一来，我们就可以实现在`IDA`的反编译窗口和汇编窗口的右键菜单中，看到并调用我们编写的功能：

<img src="https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20250824142754108.png" alt="image-20250824142754108" style="zoom:50%;" />

## 0x03. 常用功能

### ctx： 当前上下文

在上面编写`UI`的过程中，我们能在一个动作的`activate`和`action`中看到这个`ctx`，这其实就是上下文。我们能从当前触发的上下文取出一些数据，这里列出如下所示：

| 属性 (Attribute)  | 类型 (Type)    | 描述 (Description)                                           | 枚举值 (Enum Values)                                         |
| ----------------- | -------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `ctx.cur_ea`      | `ea_t` (整数)  | 当前光标所在位置的有效地址 (Effective Address)。             | N/A                                                          |
| `ctx.widget_type` | `int` (枚举)   | 当前触发动作的窗口/部件 (Widget) 的类型。用于判断上下文。    | `BWN_DISASM`: 反汇编窗口<br>`BWN_PSEUDOCODE`: 伪代码窗口<br>`BWN_HEXVIEW`: 十六进制窗口<br>`BWN_STRUCTS`: 结构体窗口<br>`BWN_ENUMS`: 枚举窗口<br />`BWN_FUNCS`: 函数列表窗口 |
| `ctx.widget`      | `TWidget*`     | 指向当前窗口/部件对象的指针。可用于更高级的窗口操作。        | N/A                                                          |
| `ctx.cur_sel`     | `(ea_t, ea_t)` | 元组，表示用户选择的范围 `(start, end)`。若无选择，起始地址为 `BADADDR`。 | N/A                                                          |
| `ctx.cur_func`    | `func_t*`      | 指向光标所在位置的函数对象 (`func_t`)。如果不在函数中，则为 `None`。 | N/A                                                          |
| `ctx.cur_struc`   | `struc_t*`     | (在结构体窗口中) 指向当前结构体对象的指针。                  | N/A                                                          |
| `ctx.cur_strmem`  | `member_t*`    | (在结构体窗口中) 指向当前结构体成员对象的指针。              | N/A                                                          |
| `ctx.cur_enum`    | `enum_t*`      | (在枚举窗口中) 指向当前枚举对象的指针。                      | N/A                                                          |

### Action 状态控制

| 常量 (Constant)          | 作用 (Effect)   | 详细说明 (Detailed Explanation)                              |
| ------------------------ | --------------- | ------------------------------------------------------------ |
| `AST_ENABLE_ALWAYS`      | 始终启用        | 强制启用该 Action，无论当前上下文是什么。这是最强的启用状态。 |
| `AST_ENABLE_FOR_WIDGET`  | 在当前窗口启用  | 仅在当前拥有焦点的窗口/部件 (Widget) 中启用该 Action。当焦点切换到其他窗口时，IDA 会重新调用 `update` 并根据返回值决定新状态。 |
| `AST_ENABLE`             | 启用 (一般情况) | 与 `AST_ENABLE_ALWAYS` 类似，但强度稍弱，IDA 在某些情况下可能会根据其他上下文覆盖此状态。通常建议使用 `AST_ENABLE_FOR_WIDGET` 或 `AST_ENABLE_ALWAYS`。 |
| `AST_DISABLE_ALWAYS`     | 始终禁用        | 强制禁用 (置灰) 该 Action，无论当前上下文是什么。            |
| `AST_DISABLE_FOR_WIDGET` | 在当前窗口禁用  | 仅在当前拥有焦点的窗口中禁用该 Action。这是实现上下文相关菜单项（例如“仅在反汇编窗口可用”）的关键。 |
| `AST_DISABLE`            | 禁用 (一般情况) | 与 `AST_DISABLE_ALWAYS` 类似，但为一般禁用状态。             |
| `AST_HIDE_ALWAYS`        | 始终隐藏        | 将 Action 从菜单和工具栏中完全移除，使其不可见。             |
| `AST_HIDE_FOR_WIDGET`    | 在当前窗口隐藏  | 在当前拥有焦点的窗口中隐藏该 Action。例如，可以让某个功能在反汇编窗口可见，但在伪代码窗口中完全消失。 |
| `AST_HIDE`               | 隐藏 (一般情况) | 与 `AST_HIDE_ALWAYS` 类似的一般隐藏状态。                    |
| `AST_CHECKED`            | 勾选状态        | **这是一个标志位**，不能单独使用。必须与一个启用状态通过**按位或** (`|`) 操作结合，用于将一个可勾选的 (Checkable) Action 设置为勾选状态。 |

### 函数操作

| 函数名                    | 作用                                   |
| ------------------------- | -------------------------------------- |
| `ida_funcs.get_func`      | 通过函数地址获得函数，返回值为`func_t` |
| `ida_funcs.get_func_name` | 通过函数地址获得函数名称               |
| `.start_ea`               | 通过`func_t`获得函数的起始地址         |
| `.end_ea`                 | 通过`func_t`获得函数的结束地址         |
| `idc.get_name_ea_simple`  | 通过函数名称获得地址                   |











