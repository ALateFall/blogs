[toc]

# C_API

## 文件类

### 列出文件夹下文件(Linux)

头文件

```C
#include <dirent.h>
```

变量定义：

```C
DIR* dir = opendir("/proc"); // 文件夹
struct dirent* entry; //遍历到的文件。其中entry->d_name为文件名
entry = readdir(dir); // 在指定目录下读取一个文件
closedir(dir); //关闭文件夹
```

`tldr`：

```C
DIR *dir;
struct dirent* entry;

// open the /proc
dir = opendir("/proc");

if(dir){
    // scan files in /proc
    while((entry = readdir(dir)) != NULL){
        if(strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
            printf("filename: %s\n", entry->d_name);
        }
    }
    closedir(dir);
}else{
    perror("open /proc failed.\n");
    return -1;
}
```

### 判断文件是文件还是文件夹

头文件：

```C
#include <sys/stat.h>
```

变量定义：

```C
struct stat file_stat; // 文件状态的struct，其中file_stat->st_mode可以用来判断文件类型
stat(const char* path, struct stat* buffer); // 获取指定文件的数据信息，存储在buffer中。返回值为0表示访问成功。
S_ISREG(mode_t mode); // 一个宏，用于判断其是否是文件
S_ISDIR(mode_t mode); // 同理判断是否是文件夹
```

`tldr`：

```C
const char *path = "/path/to/file_or_directory";

struct stat file_stat;

// 获取文件信息
if (stat(path, &file_stat) == 0) {
    // 判断文件类型
    if (S_ISREG(file_stat.st_mode)) {
        printf("%s is a regular file.\n", path);
    } else if (S_ISDIR(file_stat.st_mode)) {
        printf("%s is a directory.\n", path);
    } else {
        printf("%s is neither a regular file nor a directory.\n", path);
    }
} else {
    perror("stat");
    return 1;
}
```

## 字符串类

### 分割字符串函数

头文件：

```C
#include <string.h>
```

变量定义：

```C
char* strtok(char* str, const char* split); // 以split来分隔str，返回值是第一个被分隔出来的字符串。
// 注意，该操作会将原字符串中被匹配到的split修改为'\0'。该函数含有一个静态指针，多次分隔同一字符串时第一个参数只需要设置为NULL。
```

`tldr`：

```C
char str[] = "Hello,World,How,Are,You";
char *token;

token = strtok(str, ",");
while (token != NULL) {
    printf("%s\n", token);
    token = strtok(NULL, ",");
}
```

