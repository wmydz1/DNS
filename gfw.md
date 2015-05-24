# 深入理解GFW：DNS污染
来源： 石新宇*Googler的日志
原文地址http://gfwrev.blogspot.com/2009/11/gfwdns.html
 我对最后的国家级反射放大式拒绝服务攻击器感到非常有兴趣，前几天还尝试做一个洪水攻击器未果，以后可以尝试一下哈哈哈

 

--------------------------------------------------------------------------------------------------------------------------------------------

初识DNS污染
翻墙新手们往往遇到这样的问题：我明明已经设置了socks代理为127.0.0.1:xxxx，为什么还是上不去youtube？这时经验丰富的翻墙高手就会告诉你：firefox需要设置network.proxy.socks_remote_dns为true，也就是远程解析域名。这是怎样一回事呢？为什么要远程解析？这就涉及到了GFW的DNS污染技术。

DNS（Domain Name System）污染是GFW的一种让一般用户由于得到虚假目标主机IP而不能与其通信的方法，是一种DNS缓存投毒攻击（DNS cache poisoning）。其工作方式是：对经过GFW的在UDP端口53上的DNS查询进行入侵检测，一经发现与关键词相匹配的请求则立即伪装成目标域名的解析服务器（NS，Name Server）给查询者返回虚假结果。由于通常的DNS查询没有任何认证机制，而且DNS查询通常基于的UDP是无连接不可靠的协议，查询者只能接受最先到达的格式正确结果，并丢弃之后的结果。对于不了解相关知识的网民来说也就是，由于系统默认使用的ISP提供的NS查询国外的权威服务器时被劫持，其缓存受到污染，因而默认情况下查询ISP的服务器就会获得虚假IP；而用户直接查询境外NS（比如OpenDNS）又可能被GFW劫持，从而在没有防范机制的情况下仍然不能获得正确IP。然而对这种攻击有着十分简单有效的应对方法：修改Hosts文件。但是Hosts文件的条目一般不能使用通配符（例如*.blogspot.com），而GFW的DNS污染对域名匹配进行的是部分匹配不是精确匹配，因此Hosts文件也有一定的局限性，网民试图访问这类域名仍会遇到很大麻烦。

提到的报文监听工具，以及参考其DNS劫持诊断一节。在Wireshark的filter一栏输入udp.port eq 53可以方便地过滤掉其他无关报文。为了进一步减少干扰，我们选择一个并没有提供域名解析服务的国外IP作为目标域名解析服务器，例如129.42.17.103。运行命令nslookup -type=A www.youtube.com 129.42.17.103。如果有回答，只能说明这是GFW的伪造回答，也就是我们要观测和研究的对象。

伪包特征
经过一番紧密的查询，我们可以发现GFW返回的IP取自如下列表：

4.36.66.178203.161.230.171211.94.66.147202.181.7.85202.106.1.2209.145.54.50216.234.179.1364.33.88.161

关于这八个特殊IP，鼓励读者对这样两个问题进行探究：1、为什么是特定的IP而不是随机IP，固定IP和随机IP各自有什么坏处；2、为什么就是这8个IP不是别的IP，这8个IP为什么倒了GFW的霉？关于搜索这类信息，除了www.google.com之外，www.bing.com有专门的搜索IP对应网站的功能，使用方法是输入ip:IP地址搜索。www.robtex.com则是一个专门收集域名解析信息的网站。欢迎读者留下自己的想法和发现:lol:。

从Wireshark收集到的结果分析（实际上更好的办法是，将结果保存为pcap文件，或者直接使用tcpdump，由tcpdump显示成文本再自行提取数据得到统计），我们将GFW发送的DNS污染包在IP头部的指纹特征分为两类：

一型：
ip_id == ____（是一个固定的数，具体数值的查找留作习题）。
没有设置“不分片”选项。
没有设置服务类型。
对同一对源IP、目标IP，GFW返回的污染IP在上述8个中按照给出的顺序循环。与源端口无关、与源IP目标IP对相关。
TTL返回值比较固定。TTL为IP头部的“Time to Live”值，每经过一层路由器这个值会减1，TTL为1的IP包路由器将不再转发，多数路由器会返回源IP一条“ICMP time to live exceed in transit”消息。
二型：
每个包重复发送3次。
没有设置“不分片”选项。
设置了“保障高流量”服务类型。
(ip_id + ? * 13 + 1) % 65536 == 0，其中?为一个有趣的未知数。ip_id在同一个源IP、目标IP对的连续查询之间以13为单位递减、观测到的ip_id的最小值和最大值分别为65525（即-11，溢出了!）和65535。
对同一对源IP、目标IP，GFW返回的污染IP在上述8个中按照给出的顺序循环。与源端口无关、与源IP目标IP对相关。
对同一对源IP、目标IP，TTL返回值时序以1为单位递增。TTL在GFW发送时的取值有64种。注：源IP接收到的包的TTL被路由修改过，所以用户观测到的TTL不一定只有64种取值，这是由于网络拓扑变化的原因导致的。一型中的“比较固定”的“比较”二字也是考虑到网络拓扑偶尔的变化而添加的，也许可以认为GFW发送时的初始值是恒定的。
（以上结果仅保证真实性，不保证时效性，GFW的特征随时有可能改变，尤其是时序特征与传输层特征相关性方面。最近半年GFW的特征在很多方面的变化越来越频繁，在将来介绍TCP阻断时我们会提到。）

还可以进行的实验有：由于当前二型的TTL变化范围是IP个数的整数倍，通过控制DNS查询的TTL使得恰好有GFW的返回（避免动态路由造成的接收者观察到的TTL不规律变化），观察IP和TTL除以8的余数是否有对应关系，在更改源IP、目标IP对之后这个关系是否仍然成立。这关系到的GFW负载平衡算法及响应计数器（hit counter）的独立性和一致性。事实上对GFW进行穷举给出所有关于GFW的结果也缺乏意义，这里只是提出这样的研究方法，如果读者感兴趣可以继续探究。

每次查询通常会得到一个一型包和三个完全相同的二型包。更换查询命令中type=A为type=MX或者type=AAAA或者其它类型，可以看到nslookup提示收到了损坏的回复包。这是因为GFW的DNS污染模块做得十分粗制滥造。GFW伪造的DNS应答的ANSWER部分通常只有一个RR组成（即一条记录），这个记录的RDATA部分为那8个污染IP之一。对于二型，RR记录的TYPE值是从用户查询之中直接复制的。于是用户就收到了如此奇特的损坏包。DNS响应包的UDP荷载内容特征：

一型
DNS应答包的ANSWER部分的RR记录中的域名部分由0xc00c指代被查询域名。
RR记录中的TTL设置为5分钟。
无论用户查询的TYPE是什么，应答包的TYPE总是设置为A（IPv4地址的意思）、CLASS总是设置为IN。
二型
DNS应答包的ANSWER部分的RR记录中的域名部分是被查询域名的全文。
RR记录中的TTL设置为1天。
RR记录中的TYPE和CLASS值是从源IP发送的查询复制的。
其中的术语解释：RR = Resource Record：dns数据包中的一条记录；RDATA = Resource Data：一条记录的数据部分；TYPE：查询的类型，有A、AAAA、MX、NS等；CLASS：一般为IN[ternet]。

触发条件
实际上DNS还有TCP协议部分，实验发现，GFW还没有对TCP协议上的DNS查询进行劫持和污染。匹配规则方面，GFW进行的是子串匹配而不是精确匹配，并且GFW实际上是先将域名转换为字符串进行匹配的。这一点值得特殊说明的原因是，DNS中域名是这样表示的：一个整数n1代表以“.”作分割最前面的部分的长度，之后n1个字母，之后又是一个数字，若干字母，直到某次的数字为0结束。例如www.youtube.com则是"\x03www\x07youtube\x03com\x00"。因此，事实上就可以观察到，对www.youtube.coma的查询也被劫持了。

现状分析
4.36.66.178，关键词。whois：Level 3 Communications, Inc. 位于Broomﬁeld, CO, U.S.
203.161.230.171，关键词。whois：POWERBASE-HK位于Hong Kong, HK.
211.94.66.147，whois：China United Network Communications Corporation Limited位于Beijing, P.R. China.
202.181.7.85，关键词。whois：First Link Internet Services Pty Ltd.位于North Rocks, AU.
202.106.1.2,whois：China Unicom Beijing province network位于Beijing, CN.
209.145.54.50，反向解析为dns1.gapp.gov.cn，新闻出版总署的域名解析服务器？目前dns1.gapp.gov.cn现在是219.141.187.13在bjtelecom。whois：World Internet Services位于San Marcos, CA, US.
216.234.179.13，关键词。反向解析为IP-216-234-179-13.tera-byte.com。whois：Tera-byte Dot Com Inc.位于Edmonton, AB, CA.
64.33.88.161，反向解析为tonycastro.org.ez-site.net, tonycastro.com, tonycastro.net, thepetclubfl.net。whois：OLM,LLC位于Lisle, IL, U.S.
 

可见上面的IP大多数并不是中国的。如果有网站架设到了这个IP上，全中国的Twitter、Facebook请求都会被定向到这里——好在GFW还有HTTP URL关键词的TCP阻断——HTTPS的请求才构成对目标IP的实际压力，相当于中国网民对这个IP发起DDoS攻击，不知道受害网站、ISP是否有索赔的打算？

我们尝试用bing.com的ip反向搜索功能搜索上面那些DNS污染专用IP，发现了一些有趣的域名。显然，这些域名都是DNS污染的受害域名。

例如倒霉的edoors.cn.china.cn，宁波中国门业网，其实是因为edoors.cn被dns污染。一起受害的还有chasedoors.cn.china.cn，美国蔡斯门业（深圳）有限公司。
还有*.sf520.com，似乎是一个国内的游戏私服网站。www.sf520.com也是一个私服网站。可见国内行政体系官商勾结之严重，一个“国家信息安全基础设施”竟然还会用来保护一些网游公司的利益。
此外还有一些个人blog。www.99tw.net也是一个游戏网站。
还有www.why.com.cn，名字起得好。
还有www.999sw.com 广东上九生物降解塑料有限公司生物降解树脂|增粘母料|高效保水济|防洪 邮编:523128……这又是怎么一回事呢？不像是被什么反动网站连坐的。还有人问怎么回事怎么会有那么多IP结果。
www.facebook.comwww.xiaonei.com，怎么回事呢？其实是因为有人不小心把两个地址连起来了，搜索引擎以为这是一个链接，其实这个域名不存在，但是解析的时候遭到了污染，就以为存在这个域名了。
倒霉的www.xinsheng.net.cn——武汉市新胜电脑有限公司，因为www.xinsheng.net被连坐。
DNS劫持的防范和利用
之前我们已经谈到，GFW是一套入侵检测系统，仅对流量进行监控，暂没有能力切断网络传输，其“阻断”也只是利用网络协议容易被会话劫持（Session hijacking）的弱点来进行的。使用无连接UDP的DNS查询只是被GFW抢答了，真正的答案就跟在后面。于是应对GFW这种攻击很自然的想法就

