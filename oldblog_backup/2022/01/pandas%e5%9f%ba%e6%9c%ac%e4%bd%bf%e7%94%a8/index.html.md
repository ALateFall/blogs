---
layout: post
title: pandas基本使用
date: 2022-01-26
tags: ["玄学"]
---

[toc]

# Pandas库的基本使用

## 创建、读取以及写入文件

pandas中有两个数据类型，一个是DataFrame，另一个是Series，可以简单理解为DataFrame是一个每一行和列带名字的矩阵，而Series是只有一列的DataFrame。

### 创建DataFrame

可以直接向pd.DataFrame()传入字典：

    fruits = pd.DataFrame({'Apples': [30], 'Bananas': [21]})

    """
        Apples  Bananas
    0   30      21
    """

也可以接受列表：

DataFrame可以接受columns和index参数，从而分别指定列、行的名称：

    fruit_sales = pd.DataFrame([[35,21],[41,34]], index=['2017 Sales', '2018 Sales'], columns=['Apples', 'Bananas'])

    """
                Apples  Bananas
    2017 Sales  35      21
    2018 Sales  41      34
    """

### 创建Series

接受列表：

    ingredients = pd.Series(['4 cups', '1 cup', '2 large', '1 can'], index=['Flour', 'Milk', 'Eggs', 'Spam'], name='Dinner', dtype=object)

    """
    Flour     4 cups
    Milk       1 cup
    Eggs     2 large
    Spam       1 can
    Name: Dinner, dtype: object
    """

### 读取csv文件：read_csv()函数

接受参数是csv的路径，返回值是csv读取后的dataframe。

    reviews = pd.read_csv('../input/wine-reviews/winemag-data_first150k.csv', index_col=0)

### 写入csv文件：to_csv()函数

同上，只不过是写入文件。

    animals = pd.DataFrame({'Cows': [12, 20], 'Goats': [22, 19]}, index=['Year 1', 'Year 2'])
    animals.to_csv('cows_and_goats.csv')

## 选择数据

### 选取某列数据

pandas提供了两种选取DataFrame里面的数据的方式，其一是使用字典的方式索引，其二是直接调用属性。

示例：

    reviews.country

    """
    0            Italy
    1         Portugal
                ...   
    129969      France
    129970      France
    Name: country, Length: 129971, dtype: object
    """

或者：

    reviews["country"]

    """
    0            Italy
    1         Portugal
                ...   
    129969      France
    129970      France
    Name: country, Length: 129971, dtype: object
    """

### 选取某个元素

这里是接上面，先选取某一列，再选取某一行的。

pandas还提供了其他方式选取具体某个数据，可以参见下面的"选取某一行"。

    reviews['country'][0]

    """
    'Italy'
    """

### 选取某一行（索引）

pandas提供了两个属性来实现这一基本功能：iloc属性和loc属性。

注意，这里是属性而不是函数，因此使用[]索引而不是()

### iloc属性

整体和numpy的索引方式差不多。

可以像这样子索引：

    reviews.iloc[1, 0]

表示是第1行的第0个元素。

也可以只用一个参数：

    reviews.iloc[0]

表示第一行的所有元素。

也可以在列表中传入列表：

    reviews.iloc[[0,2,3] , 0]

表示第0，2，3行的第0个元素。

### loc属性

和iloc属性类似，但是用来索引的方式，是按index名以及column名而不是第几个。

示例：

    reviews.loc["index1", "country"]

    reviews.loc[:, ['taster_name', 'taster_twitter_handle', 'points']]

**注意：iloc是左闭右开，但是loc取的是左闭右闭。**

### 操作索引的名称：set_index()函数

即给所有索引取名，而不是对索引重命名。

示例：

    reviews.set_index("title")

![image-20220125221224104](20220125221226.png)

### 条件性地选取

pandas重载了运算符，比如，==会将每一个元素与之比较，并将对应元素的位置变为True或者False。

示例：

    reviews.country == "Italy"

    """
    0          True
    1         False
              ...  
    129969    False
    129970    False
    Name: country, Length: 129971, dtype: bool
    """

利用此特性，可以用来条件选取：

    reviews.loc[reviews.country == "Italy"]

即可选出国家为"Italy"的所有行。

同样的，可以进行多条件选取，用&连接：

    reviews.loc[(reviews.country == 'Italy') & (reviews.points >= 90)]

也可以用'条件选取：

    reviews.loc[(reviews.country == 'Italy') ' (reviews.points >= 90)]

也可以使用pandas的内置函数isin()：

    reviews.loc[reviews.country.isin(['Italy', 'France'])]

### 更改元素

pandas中，元素内容、index、columns均可以进行更改。

    reviews['critic'] = 'everyone' # 更改元素内容
    reviews['critic']

    """
    0         everyone
    1         everyone
                ...   
    129969    everyone
    129970    everyone
    Name: critic, Length: 129971, dtype: object
    """

    reviews["index_backwards"] = range(len(reviews), 0, -1)
    reviews['index_backwards']

    """
    0         129971
    1         129970
               ...  
    129969         2
    129970         1
    Name: index_backwards, Length: 129971, dtype: int64
    """

## 摘要以及映射

### 摘要

pandas中，可以使用一些函数来查看每一列的数据的一些信息，例如平均值，最大值，或者不同的值的个数等等。

### decribe()函数

可以查看某一列的个数、平均值、最大值等参数。

    reviews.points.describe() # 数值类型

    """
    count    129971.000000
    mean         88.447138
                 ...      
    75%          91.000000
    max         100.000000
    Name: points, Length: 8, dtype: float64
    """

    reviews.taster_name.describe() # 字符串类型

    """
    count         103727
    unique            19
    top       Roger Voss
    freq           25514
    Name: taster_name, dtype: object
    """

### mean()函数

查看某一列的平均值。

    reviews.points.mean()

    """
    88.44713820775404
    """

### unique()函数

查看某一列中只出现一次的值。

    reviews.taster_name.unique()

    """
    array(['Kerin O'Keefe', 'Roger Voss', 'Paul Gregutt',
           'Alexander Peartree', 'Michael Schachner', 'Anna Lee C. Iijima',
           'Virginie Boone', 'Matt Kettmann', nan, 'Sean P. Sullivan',
           'Jim Gordon', 'Joe Czerwinski', 'Anne Krebiehl\xa0MW',
           'Lauren Buzzeo', 'Mike DeSimone', 'Jeff Jenssen',
           'Susan Kostrzewa', 'Carrie Dykes', 'Fiona Adams',
           'Christina Pickard'], dtype=object)
    """

### value_counts()函数

查看某一列中每个值出现的次数。

    reviews.taster_name.value_counts()

    """
    Roger Voss           25514
    Michael Schachner    15134
                         ...  
    Fiona Adams             27
    Christina Pickard        6
    Name: taster_name, Length: 19, dtype: int64
    """

### 映射

在dataframe中，若想对某一列的数值均进行某种操作，可以使用映射的方式。

一般由两个函数实现，即map()函数以及apply()函数。

### map()函数

一般是和lambda函数配合使用。

示例，假如想让reviews.poinits列中，每一个数字都减去平均值：

    reviews_points_mean = reviews.points.mean()
    reviews.point.map(lambda p: p - review_points_mean)

    """
    0        -1.447138
    1        -1.447138
                ...   
    129969    1.552862
    129970    1.552862
    Name: points, Length: 129971, dtype: float64
    """

### apply()函数

和map函数差不多，但是支持自定义函数。

    def remean_points(row):
        row.points = row.points - review_points_mean
        return row

    reviews.apply(remean_points, axis='columns')

### 更便捷的方法

pandas重载了运算符。

例如，假如想让reviews.poinits列中，每一个数字都减去平均值，用map函数可以实现，但是可以直接以运算符的方式更简单地实现：

    reviews.points - reviews.points.mean()

## 聚类和排序

### by()函数

### groupby()函数

dataframe的内置方法，可以将dataframe按照传入的参数这一列进行聚类，index变为传入参数。

可以传入一个列表，使其以多个索引的方式存在。

例如，一个dataframe中，要查看叫做taster_twitter_handle这一列中，每一个种类的具体数量：

    reviews_written = reviews.groupby('taster_twitter_handle').taster_twitter_handle.count()
    print(reviews_written)

    """
    result:
    taster_twitter_handle
    @AnneInVino          3685
    @JoeCz               5147
    @bkfiona               27
    @gordone_cellars     4177
    @kerinokeefe        10776
    @laurbuzz            1835
    @mattkettmann        6332
    @paulgwine           9532
    @suskostrzewa        1085
    @vboone              9537
    @vossroger          25514
    @wawinereport        4966
    @wineschach         15134
    @winewchristina         6
    @worldwineguys       1005
    Name: taster_twitter_handle, dtype: int64
    """

又例如，对于每一个价格，获取它的最高分数，就先分组，然后对分数取最大值：

    best_rating_per_price = reviews.groupby("price").points.max().sort_index()
    print(best_rating_per_price)

    """
    price
    4.0       86
    5.0       87
    6.0       88
    7.0       91
    8.0       91
              ..
    1900.0    98
    2000.0    97
    2013.0    91
    2500.0    96
    3300.0    88
    Name: points, Length: 390, dtype: int64
    """

### agg()函数

可以对dataframe的数据类型指定的一列，同时执行多个函数，如下：

    price_extremes = reviews.groupby("variety").price.agg(["min", "max"])
    print(price_extremes)

    """
                  min    max
    variety                 
    Abouriou     15.0   75.0
    Agiorgitiko  10.0   66.0
    Aglianico     6.0  180.0
    Aidani       27.0   27.0
    Airen         8.0   10.0
    ...           ...    ...
    Zinfandel     5.0  100.0
    Zlahtina     13.0   16.0
    Zweigelt      9.0   70.0
    Çalkarası    19.0   19.0
    Žilavka      15.0   15.0

    [707 rows x 2 columns]
    """

### sort_values()函数

按照值排序，比如上面的dataframe，按照min排序，再按照max排序：

    sorted_varieties = price_extremes.sort_values(by=["min", "max"], ascending=False)
    print(sorted_varieties)

    """
                                      min    max
    variety                                     
    Ramisco                         495.0  495.0
    Terrantez                       236.0  236.0
    Francisa                        160.0  160.0
    Rosenmuskateller                150.0  150.0
    Tinta Negra Mole                112.0  112.0
    ...                               ...    ...
    Roscetto                          NaN    NaN
    Sauvignon Blanc-Sauvignon Gris    NaN    NaN
    Tempranillo-Malbec                NaN    NaN
    Vital                             NaN    NaN
    Zelen                             NaN    NaN

    [707 rows x 2 columns]
    """

### 综合使用

比如，按照国家、酒的品质两个方面排序，然后计算每一个类别中的数量的降序排序。

    country_variety_counts = reviews.groupby(["country", "variety"]).size().sort_values(ascending=False)
    print(country_variety_counts)

    """
    country  variety                 
    US       Pinot Noir                  9885
             Cabernet Sauvignon          7315
             Chardonnay                  6801
    France   Bordeaux-style Red Blend    4725
    Italy    Red Blend                   3624
                                         ... 
    Mexico   Cinsault                       1
             Grenache                       1
             Merlot                         1
             Rosado                         1
    Uruguay  White Blend                    1
    Name: winery, Length: 1612, dtype: int64
    """

## 数据类型与缺失值

### 获得数据类型: dtype属性

注意这是一个属性，没有括号

    dtype = reviews.points.dtype
    print(dtype)

    """
    int64
    """

### 更改数据类型：astype方法

这是一个方法，即一个函数

    point_strings = reviews.points.astype(str)
    print(point_strings)

    """
    0         87
    1         87
    2         87
    3         87
    4         87
              ..
    129966    90
    129967    90
    129968    90
    129969    90
    129970    90
    Name: points, Length: 129971, dtype: object

    """

### isna()函数

对于每一个元素，判断是否是缺失值，是的话对应元素为True，反之为False。

示例，对于reviews中的price列，判断是否是缺失值：

    print(reviews.price.isna())

    """
    0          True
    1         False
    2         False
    3         False
    4         False
              ...  
    129966    False
    129967    False
    129968    False
    129969    False
    129970    False
    Name: price, Length: 129971, dtype: bool
    """

判断points列中，是缺失值的元素的数目：

    n_missing_prices = reviews.price.isna().sum()
    print(n_missing_prices)

    """
    8996
    """

### fillna()函数

填充缺失值。返回值是填充后的整个dataframe。

示例，填充region_1列的缺失值，并计算region_1中每一种数据的数量，再降序排序：

    reviews_per_region = reviews.region_1.fillna("Unknown").value_counts().sort_values(ascending=False)
    print(reviews_per_region)

    """
    Unknown                 21247
    Napa Valley              4480
    Columbia Valley (WA)     4124
    Russian River Valley     3091
    California               2629
                            ...  
    Offida Rosso                1
    Corton Perrières            1
    Isle St. George             1
    Geelong                     1
    Paestum                     1
    Name: region_1, Length: 1230, dtype: int64
    """

## 重命名和结合

### rename()函数

可以修改columns的名字或者index的名字。

rename()函数可以接受columns参数或者index参数，但是index一般有其他的方法修改，因此一般用于columns。

rename函数可以接受多种数据类型的参数，最常用的数据类型是字典，比较方便。

返回值是更改后的dataframe。

示例：

    #将region_1列名修改为region, 将region_2列修改为locale

    renamed = reviews.rename(columns={"region_1": "region", "region_2": "locale"})

### rename_axis()函数

用于修改index的名字。返回值是修改后的dataframe。

注意，它不是修改的0,1,2,3这种索引，只是给它上面加了个名字。

示例：

    reindexed = reviews.rename_axis("wines", axis="rows")

    """
             country                                        description  \
    wines                                                                 
    0          Italy  Aromas include tropical fruit, broom, brimston...   
    1       Portugal  This is ripe and fruity, a wine that is smooth...   
    2             US  Tart and snappy, the flavors of lime flesh and...   
    3             US  Pineapple rind, lemon pith and orange blossom ...   
    4             US  Much like the regular bottling from 2012, this...   
    """

### concat()函数

用于将两个dataframe连接起来，返回值是连接后的dataframe。

传入参数是一个列表，其中包含要连接的dataframe。

示例：

    combined_products = pd.concat([gaming_products, movie_products])

### join()函数

join()函数是连接两个dataframe, 但是是按照index相连，即index必须一样。

示例：

    # 先将索引设为MeetID
    powerlifting_combined = powerlifting_meets.set_index("MeetID").join(powerlifting_competitors.set_index("MeetID"))