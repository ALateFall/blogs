## Warning

根据`jyy`老师的要求，作业不应开源。由于本人的`gitbook`会自动同步，因此若你在学习此课程期间在互联网上找到了此文件，请遵循老师的原则，不主动查看此代码。本文件仅为便于本人在不同设备间同步而创建。

```C
#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>

struct process
{
    int pid;
    int ppid;
    char name[20];
};

void print_tab(int count)
{
    for (int i = 0; i < count; i++)
    {
        printf("\t");
    }
}

void print_tree(struct process *p, int pid, int length, int level)
{
    for (int i = 0; i < length; i++)
    {
        if (p[i].pid == pid)
        {
            print_tab(level);
            printf("%s\n", p[i].name);
        }
    }
    for (int i = 0; i < length; i++)
    {
        if (p[i].ppid == pid)
        {
            print_tree(p, p[i].pid, length, level + 1);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        if(argc == 2 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))){
            printf("pstree (PSmisc) UNKNOWN\n");
            printf("Copyright (C) 1993-2019 Werner Almesberger and Craig Small\n\n");
            printf("PSmisc comes with ABSOLUTELY NO WARRANTY.\n");
            printf("This is free software, and you are welcome to redistribute it under the terms of the GNU General Public License.\n");
            printf("For more information about these matters, see the files named COPYING.\n");
            return 0;
        }

        printf("Invalid Paramater. Use pstree-64 --help to get help.\n");
        return 0;
    }
    
    /* read dirnames in /proc */
    DIR *dir;
    struct dirent *entry;

    // open the /proc
    dir = opendir("/proc");
    struct process p[500];
    int process_count = 0;

    if (dir)
    {
        // scan files in /proc
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                // assert if it is dir
                struct stat file_stat;
                char full_name[20] = "/proc/";
                if (stat((const char *)strcat(full_name, entry->d_name), &file_stat) == 0)
                {
                    if (S_ISDIR(file_stat.st_mode) && (entry->d_name[0] >= '0' && entry->d_name[0] <= '9'))
                    {
                        // it's a directory
                        FILE *file = fopen(strcat(full_name, "/status"), "r");
                        if (file)
                        {
                            int count = 0;
                            char line[256];
                            while (fgets(line, sizeof(line), file))
                            {
                                char *value = strchr(line, ':') + 1;
                                while (*value == ' ' || *value == '\t')
                                {
                                    value++;
                                }
                                char *rm_line = value;
                                while (*rm_line != '\n')
                                {
                                    rm_line++;
                                }
                                *rm_line = '\0';

                                switch (count)
                                {
                                case 0:
                                {
                                    strcpy(p[process_count].name, value);
                                    break;
                                }
                                case 5:
                                {
                                    p[process_count].pid = atoi(value);
                                    break;
                                }
                                case 6:
                                {
                                    p[process_count].ppid = atoi(value);
                                    break;
                                }
                                }

                                if (count++ == 6)
                                {
                                    process_count++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
    }
    else
    {
        perror("open /proc failed.\n");
        return -1;
    }

    print_tree(p, 1, process_count, 0);

    return 0;
}
```

