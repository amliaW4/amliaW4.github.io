
title: IDA ImportError

date: 2018-03-21 14:12:59

categories: 
- tools
- IDA

今天安装 findcrypt3 时候 出现 ImportError 。

findcrypt3 需要 pip install yrar-python ， 但是 pip 包安装路径没有在 IDA 的 sys.path 路径中。

查看 IDA 搜索包的路径：

```python
sys.path
```

添加路径后 ，没有出现错误：

```python
sys.path.append("pip包安装路径")
import yara  
```



当Python执行import语句时，它会在一些路径中搜索Python模块和扩展模块。就是 sys.path中的路径。

当安装第三方模块的时候，如果不是按照标准方式安装，则为了能够引用（import）这些模块，必须将这些模块的安装路径添加到sys.path中，

找到含有 site-packages 路径中的 .pth 文件， 添加 pip 安装路径。

还有多种添加到 sys.path 的方法可以参考一下面的文章。

参考：

http://blog.csdn.net/gqtcgq/article/details/49365933

