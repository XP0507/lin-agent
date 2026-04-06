"""
CyberStrike-Agent Skills Module
CTF 技能管理模块 - 技能定义、自动识别和策略注入
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple


@dataclass
class SkillProfile:
    name: str
    description: str
    category: str = ""
    keywords: List[str] = field(default_factory=list)
    strategy: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


class SkillManager:

    def __init__(self):
        self.skills: Dict[str, SkillProfile] = self._init_default_skills()

    def _init_default_skills(self) -> Dict[str, SkillProfile]:
        return {
            "ctf-pwn": SkillProfile(
                name="ctf-pwn",
                description="二进制漏洞利用 - 栈溢出、堆利用、ROP链构造、格式化字符串、UAF等底层漏洞的发现与利用",
                category="pwn",
                keywords=[
                    "pwn", "binary", "elf", "溢出", "overflow", "stack overflow", "栈溢出",
                    "heap", "堆", "uaf", "use after free", "double free", "fastbin", "tcache",
                    "rop", "ret2text", "ret2libc", "ret2csu", "ret2dlresolve",
                    "canary", "nx", "pie", "relro", "got", "plt", "got覆写",
                    "format string", "格式化字符串", "fsb", "fmtstr",
                    "shellcode", "pwntools", "one_gadget", "gadget",
                    "unlink", "house of force", "house of einherjar", "house of spirit",
                    "off by one", "off-by-one", "整数溢出", "integer overflow",
                    "seccomp", "沙箱", "orw", "srop", "sigreturn",
                    "mprotect", "mmap", "syscall", "pop rdi", "pop rsi", "pop rax",
                    "checksec", "ida", "gdb", "gef", "pwndbg", "r2", "radare2",
                    "libc", "ld.so", "动态链接", "plt表", "got表", "延迟绑定"
                ],
                tools=["bash", "python", "read_file", "write_file"],
                examples=[
                    "PWN题目，附件为ELF文件，开启了NX保护",
                    "栈溢出题目，需要绕过canary获取shell",
                    "堆题，有add/delete/edit功能，存在UAF漏洞",
                    "格式化字符串漏洞，可以读写任意地址",
                    "ret2libc，泄露libc地址后调用system('/bin/sh')"
                ],
                strategy=[
                    "【阶段1: 信息收集】执行 checksec 检查保护机制(CANARY/NX/PIE/RELRO)，用 file 确认架构(32/64位)，用 strings / readelf 提取关键符号(system/puts/printf)、危险函数(gets/read/scanf/sprintf)和有用字符串(/bin/sh/shell/flag)",
                    "【阶段2: 漏洞定位】反编译分析入口逻辑：确认输入点(buffer大小/偏移量)、边界检查是否存在缺陷(off-by-one/整数溢出)、是否有后门函数或system调用。对堆题需追踪chunk分配/释放/编辑流程，确认是否存在UAF/double-free/fastbin attack条件",
                    "【阶段3: 偏移计算】用 cyclic 生成模式串确定精确偏移：发送 cyclic(200) 触发崩溃，从崩溃地址用 cyclic_find 反推 offset。对格式化字符串漏洞用 %p.%p.%p... 确定参数偏移。对堆题计算 chunk header 大小和对齐要求",
                    "【阶段4: 保护绕过方案设计】根据 checksec 结果选择策略：",
                    "  - 无保护: 直接跳转 shellcode 或后门函数",
                    "  - 仅CANARY: 泄露 canary 值(格式化字符串/fork server/爆破)，在 payload 中正确放置",
                    "  - NX开启+无PIE: ret2libc / ret2csu / one_gadget",
                    "  - PIE开启: 需先泄露程序基址(通过 info leak 或 partial overwrite)",
                    "  - Full RELRO: 无法修改 GOT 表，考虑覆写 hook(__malloc_hook/__free_hook)",
                    "【阶段5: ret2libc 实战原子化指令】",
                    "  步骤A - 选择泄漏函数: 优先选已导入且调用过的函数(puts/write/printf)，确认其在 GOT 表中有条目",
                    "  步骤B - 构造泄漏 payload: payload = padding + pop_rdi_gadget + puts_got_addr + puts_plt_addr + main_addr(返回主函数重新利用)",
                    "  步骤C - 发送并接收: recvuntil提示符，send(payload)，recvline 获取泄漏地址",
                    "  步骤D - 计算 libc 基址: libc_base = leaked_addr - libc.symbols['puts'] (注意64位需要 u64 解码并处理字节序)",
                    "  步骤E - 计算目标地址: system_addr = libc_base + libc.symbols['system']; binsh_addr = libc_base + next(libc.search(b'/bin/sh'))",
                    "  步骤F - 构造最终 payload: payload = padding + ret_gadget(栈对齐) + pop_rdi + binsh_addr + system_addr",
                    "  步骤G - 发送获取 shell: send(final_payload); 切换到交互模式 interactive()",
                    "【阶段6: 堆利用实战原子化指令】",
                    "  UAF: free(chunk) 后指针未清空 → 可通过 edit 写入伪造 fd/bk 指针实现 fastbin dup / tcache poisoning",
                    "  Fastbin Attack: 控制目标地址附近必须有合法 size 字段; 通过 edit 覆盖 free chunk 的 fd 指向目标-0x10 附近; malloc 两次分配到达目标区域",
                    "  Tcache Poisoning(glibc 2.26+): tcache 无 double-free 检查; 可直接覆盖 fd 到任意地址实现任意写",
                    "  Unlink: 伪造 fake_chunk 的 fd=&fake_chunk-0x18, bk=&fake_chunk-0x10; 触发 unlink 时 FD->bk = BK, BK->fd = FD 实现指针覆写",
                    "【阶段7: 本地调试与远程迁移】本地用 gdb/gef/pwndgb 单步验证每一步 payload 的效果；远程迁移时注意: libc版本差异(用 LibcSearcher 或 libc-database 匹配)、ASLR导致地址随机(每次连接重新泄露)、网络延迟调整(recv/send超时)",
                    "【阶段8: 高级场景】seccomp沙箱: 用 seccomp-tools dump 分析规则，构造 orw(open→read→write) ROP链替代 execve; SROP: 利用 sigreturn frame 控制所有寄存器; ret2dlresolve: 不依赖任何泄漏直接解析符号",
                    "⚠️ 常见坑点预警:",
                    "  1. [libc版本不匹配] 远程libc与本地libc不同 → 泄漏后用 LibcSearcher 或 libc-database 匹配远程版本；若题目提供libc.so直接用该文件加载符号表",
                    "  2. [ASLR地址随机] 每次新连接地址都会变 → 不要缓存上一次的 libc_base，每次连接必须重新泄露",
                    "  3. [栈对齐] 64位下调用 system() 需要 16 字节栈对齐 → payload 中在 pop_rdi 前加一个 ret gadget (0xdeadbeef) 对齐",
                    "  4. [字节序错误] 64位泄露的地址是 little-endian → recvline 后需 u64(接收内容.ljust(8, b'\\x00')) 正确解码，否则基址计算全错",
                    "  5. [canary爆破失败] fork server 模式下 canary 不变可逐字节爆破(256次/字节)；非 fork 模式每字节有 1/256 概率猜错导致崩溃",
                    "  6. [one_gadget条件不满足] one_gadget 的约束(restrictions)在当前上下文可能不满足(rax/rbx/rcx等寄存器值不对) → 需要逐个测试或改用标准 ret2libc",
                    "  7. [堆fd/bk校验] glibc 2.32+ fastbin 增加 fd/bk 指针安全检查(对齐+size验证) → tcache poisoning 更可靠或利用 safe-linking 机制",
                    "  8. [PIE + ret2libc] PIE开启时程序自身地址也随机 → 需先泄露程序基址(通过格式化字符串/信息泄露)，再结合 libc 泄漏计算所有目标地址",
                    "  9. [recv/send超时] 远程环境网络延迟高 → 设置合理的 timeout(3-10秒)；交互模式前确认 shell 已就绪(发送 id 确认)",
                    "  10. [seccomp误判] execve 被禁用时盲目调用 system 会 crash → 先 dump 规则再决定 orw ROP 或 SROP"
                ]
            ),
            "ctf-web": SkillProfile(
                name="ctf-web",
                description="Web安全漏洞利用 - SQL注入/XSS/SSTI/SSRF/CSRF/XXE/JWT攻击/文件上传/反序列化等Web层攻击技术",
                category="web",
                keywords=[
                    "web", "http", "https", "url", "网站", "网页", "web应用",
                    "sql注入", "sqli", "sql injection", "union select", "盲注", "布尔盲注", "时间盲注", "报错注入",
                    "xss", "反射型xss", "存储型xss", "dom xss", "跨站脚本",
                    "ssti", "模板注入", "jinja2", "twig", "smarty", "freemarker", "服务端模板注入",
                    "ssrf", "服务器端请求伪造", "内网探测", "redis", "file协议",
                    "csrf", "跨站请求伪造", "token", "referer",
                    "xxe", "xml外部实体", "xml注入", "dtd",
                    "jwt", "json web token", "token伪造", "算法混淆", "none算法", "密钥弱",
                    "上传", "upload", "文件上传", "一句话木马", "webshell", ".htaccess", ".user.ini",
                    "反序列化", "unserialize", "pickle", "php序列化", "java反序列化", "pop链",
                    "包含", "lfi", "rfi", "文件包含", "本地文件包含", "远程文件包含", "伪协议", "php://filter", "data://",
                    "目录遍历", "path traversal", "../", "..\\",
                    "备份", ".bak", ".git", ".svn", ".ds_store", ".swp", "源码泄露",
                    "waf", "防火墙", "绕过", "bypass", "过滤", "黑名单",
                    "cookie", "session", "认证", "登录", "权限提升",
                    "命令注入", "rce", "代码执行", "eval", "exec", "system",
                    "curl", "wget", "burp", "sqlmap", "dirsearch", "gobuster"
                ],
                tools=["bash", "python", "http", "download", "read_file", "write_file"],
                examples=[
                    "Web题，目标URL为 http://xxx，可能存在SQL注入",
                    "登录页面，用户名密码输入框，尝试SQL注入绕过",
                    "Flask应用，参数可控，疑似SSTI模板注入",
                    "有文件上传功能，需要上传webshell获取shell",
                    "PHP站点，发现了.git源码泄露"
                ],
                strategy=[
                    "【阶段1: 信息收集与指纹识别】用 dirsearch/gobuster 扫描隐藏路径(admin/api/backup/.git/.env/config.php)；用 curl -I 获取响应头(Server/X-Powered-By/Set-Cookie)判断技术栈(PHP/Java/Python/Node.js及版本)；测试常见备份文件(.bak/.zip/.tar.gz/.old/.swp/~)和敏感文件(robots.txt/sitemap.xml/web.config/.env)",
                    "【阶段2: 参数映射与输入点枚举】列出所有可控输入点: URL路径参数(GET)、POST表单字段(JSON/form-data/x-www-form-urlencoded)、HTTP Header(Cookie/User-Agent/Referer/X-Forwarded-For)、文件上传字段。每个输入点单独测试基本异常行为(单引号/双引号/特殊字符导致的报错/行为变化)",
                    "【阶段3: SQL注入深度检测与利用】",
                    "  检测: ' OR '1'='1 / 1' AND '1'='1 / 1' ORDER BY N-- (递增N直到报错确定列数)",
                    "  联合查询: ' UNION SELECT NULL,NULL,NULL-- (列数匹配后替换为 database()/user()/version())",
                    "  数据提取: ' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--; 再查 column 和具体数据",
                    "  盲注(无回显): 布尔盲注用 SUBSTRING/MID/ASCII 逐字符判断; 时间盲注用 SLEEP/BENCHMARK 配合 IF/CASE 条件延时",
                    "  绕过WAF: /**/ 替代空格, %0a 换行, /*!50000*/ 内联注释, 大小写混合(UnIoN), 编码(URLencode/Hex/Base64), 双写(sqqlinject), 参数污染(同名参数不同值)",
                    "  报错注入(MySQL): EXTRACTVALUE(1,CONCAT(0x7e,(SELECT...))); UPDATEXML(1,CONCAT(0x7e,...)); FLOOR(rand(0)*2) group by 报错",
                    "【阶段4: SSTI/Jinja2模板注入】",
                    "  检测: {{7*7}} 返回49则确认SSTI; {{config}} 获取Flask配置含secret_key; {{self.__init__.__globals__}} 获取全局对象",
                    "  RCE路径: {{''.__class__.__mro__[2].__subclasses__()}} 枚举子类找 os._wrap_close(索引因环境不同需遍历); {{lipsum.__globals__['os'].popen('cmd').read()}} 直接命令执行",
                    "  绕过过滤: |attr('xxx') 替代 .xxx 访问属性; __cla''ss__ 拼接绕过; request|attr(args) 动态传参; {% set x=__import__('os') %} 导入模块",
                    "【阶段5: 文件上传与WebShell】",
                    "  黑名单绕过: .pHp5/.phtml/.pht (多后缀); shell.php.jpg (00截断/MIME类型欺骗); .htaccess 将jpg解析为php; .user.ini auto_prepend_file=shell.jpg",
                    "  内容检测绕过: GIF89a 头部伪装图片; 去除<?php ?>标签用 <script language='php'>; base64编码payload再用php://filter解码执行",
                    "  WebShell连接: 中国蚁剑/冰蝎/哥斯拉; 或者直接 curl POST 传参执行命令",
                    "【阶段6: SSRF内网探测】",
                    "  协议探测: file:///etc/passwd (读文件); dict://127.0.0.1:6379 (Redis); gopher:// (SMTP/MySQL/FastCGI)",
                    "  内网扫描: http://127.0.0.1:端口/ 逐个探测常见端口(80/6379/3306/8080/9000); 利用302跳转配合file协议读内网资源",
                    "  Redis利用: Gopher协议发送 SLAVEOF/CONFIG SET dir/CONFIG SET dbfilename/save 命令写crontab或ssh authorized_keys",
                    "【阶段7: 反序列化POP链】",
                    "  PHP: __wakeup/__destruct/__toString/__call 魔法方法链式调用; 常见入口: Exception/Error 对象触发 toString; 目标: file_get_contents/file_put_contents/system/passthru",
                    "  Java: Commons-Collections(CC1-CC7)/CommonsBeanutils/ShirorememberMe反序列化; 用 ysoserial 生成payload",
                    "  Python(Pickle): __reduce__ 方法执行系统命令; 注意 base64 编码传输",
                    "【阶段8: JWT安全】",
                    "  None算法: 将alg改为none删除签名段; HS256密钥混淆: 将RS256公钥作为HS256密钥签名; 密钥弱/硬编码: 用 jwt_tool 爆破或从源码/配置文件提取",
                    "  kid注入: 通过 kid 参数控制HMAC密钥; jku/header注入: 引导验证方加载攻击者控制的公钥",
                    "⚠️ 常见坑点预警:",
                    "  1. [WAF误判为无漏洞] WAF拦截了测试payload但不代表没有漏洞 → 尝试多种编码绕过(双重URLencode/Unicode/全角字符/注释混淆)；有时WAF只检测特定参数名，换参数名即可绕过",
                    "  2. [Cookie/Session丢失] 多次请求间未携带有效Cookie导致认证状态丢失 → 首次登录成功后提取 Set-Cookie；后续所有请求必须携带该 Cookie（尤其是 SSRF/内网探测时跳转后的请求）",
                    "  3. [SQL注入闭合错误] 单引号被转义或过滤 → 尝试双写('')、宽字节(%df%27)、反斜杠截断(%00或%e0)、十六进制(0x)替代字符串",
                    "  4. [SSTI过滤死胡同] 关键字(__class__/__mro__/__subclasses__)全部被过滤 → 尝试 |attr() + request.args 传参、{%set%}变量间接引用、unicode编码(\\u005f替代下划线)、 Jinja2的cycler/joiner等内置对象链",
                    "  5. [文件上传解析失败] 上传成功但无法执行 → 检查: 目录是否有写权限、上传后文件名是否被重命名(时间戳/hash)、.htaccess是否生效(apache配置可能禁止)、中间件(Nginx/Tomcat)解析规则差异",
                    "  6. [SSRF协议限制] file:// 和 gopher:// 被禁用 → 尝试 dict:// (Redis info)、http:// (内网HTTP服务)、302跳转到 file 协议；注意 URL 编码问题(二次解码)",
                    "  7. [反序列化POP链断裂] __wakeup 触发条件不满足(PHP版本差异)或 __toString 未被调用 → 检查PHP版本(7.x+ __wakeup 不再禁用属性)；手动触发: Exception::getMessage / echo $obj / 字符串拼接",
                    "  8. [JWT时间过期] 生成的token提交后返回 expired → 检查 exp/nbf/iat 字段；将 exp 设为远期时间戳或删除exp字段(none算法下)",
                    "  9. [XSS payload不触发] 反射型XSS在script标签被过滤 → 尝试事件驱动(<img/onerror=>/<svg/onload=>)、JavaScript伪协议(href/src/action)、CSS expression(IE)、模板字符串(``)",
                    "  10. [盲注效率极低] 逐字符盲注太慢 → 优先尝试报错注入；布尔盲注用二分法减少查询次数；考虑 sqlmap --technique=B 自动化"
                ]
            ),
            "ctf-crypto": SkillProfile(
                name="ctf-crypto",
                description="密码学分析与攻击 - RSA/ECC/AES/RSA变体/哈希碰撞/流密码/编码攻击等数学密码学问题求解",
                category="crypto",
                keywords=[
                    "crypto", "密码学", "加密", "解密", "cipher",
                    "rsa", "rsa公钥", "rsa私钥", "大数分解", "factordb", "yafu", "cado-nfs",
                    "n", "e", "c", "phi", "d", "模数", "指数", "密文", "明文",
                    "小指数攻击", "small e", "e=3", "broadcast", "共模攻击", "common modulus", "wiener", "boneh-durfee",
                    "fermat", "费马分解", "pollard p-1", "pollard rho", "williams p+1",
                    "aes", "des", "3des", "ecb", "cbc", "ctr", "ofb", "cfb", "gcm", "padding oracle",
                    "iv", "nonce", "key", "block cipher", "分组密码", "填充", "pkcs7", "pkcs5",
                    "xor", "异或", "otp", "一次性密码本", "rc4", "流密码", "lfsr",
                    "hash", "md5", "sha1", "sha256", "sha512", "哈希", "摘要", "碰撞", "length extension",
                    "ecc", "椭圆曲线", "离散对数", "ecdsa", "sm2", "nacl", "curve25519",
                    "dh", "diffie-hellman", "密钥交换", "中间人", "小 subgroup",
                    "lwe", "格密码", "lattice", "ntru", "同态加密", "paillier", "elgamal",
                    "base64", "base32", "base16", "base58", "base85", "编码",
                    "rot13", "凯撒", "caesar", "维吉尼亚", "vigenere", "playfair",
                    "栅栏", "rail fence", "摩尔斯", "morse", "培根", "bacon",
                    "z3", "约束求解", "sage", "sympy", "gmpy2", "pycryptodome", "number theory"
                ],
                tools=["python", "read_file", "write_file", "bash"],
                examples=[
                    "RSA加密，已知n/e/c，需要解密得到flag",
                    "给了一个pcap包，里面是加密通信流量，需要分析加密方式",
                    "AES加密，但IV似乎有问题",
                    "XOR加密的密文，不知道密钥",
                    "RSA的e很小，可能是小指数攻击"
                ],
                strategy=[
                    "【阶段1: 算法识别与参数提取】首先明确加密算法(RSA/AES/DES/XOR/自定义)和工作模式(ECB/CBC/CTR/GCM)。提取所有公开参数(n/e/c/iv/key片段/hint)。对于RSA: 从证书/PEM文件中解析 n,e,c; 对于对称加密: 确定密钥长度(128/192/256)、模式、IV/nonce是否可控",
                    "【阶段2: RSA 攻击决策树】",
                    "  e=3 且 m^e < n: 直接开立方根 m = c^(1/e) (gmpy2.iroot)",
                    "  多组密文同一明文不同e(互质): 广播攻击(Hastad) — 用中国剩余定理合并后开根",
                    "  同一n不同e1/e2加密同一消息: 共模攻击 — 扩展欧几里得求 s1,s2 使 m = c1^s1 * c2^s2 mod n",
                    "  d 很小(d < n^0.25): Wiener 连分数攻击 — 将 e/n 展开为连分数逐项测试",
                    "  d 稍大(d < n^0.292): Boneh-Durfee 攻击(改进Wiener)",
                    "  p,q 接近(p-q很小): Fermat 因式分解 — 从 ceil(sqrt(n)) 开始搜索",
                    "  p-1 有小因子: Pollard's p-1 算法",
                    "  n 中间部分已知: 已知部分因子攻击(Coppersmith)",
                    "  低解密指数/低公钥指数: Coppersmith 定理相关方法",
                    "  通用分解: factordb.com 在线查询; 本地用 yafu/cado-nfs/sage",
                    "【阶段3: AES/分组密码攻击】",
                    "  ECB模式: 相同明文块产生相同密文块(可观察模式); 字节翻转攻击: 修改前一块密文改变后一明文块的对应位置",
                    "  CBC模式: 位翻转攻击(翻转IV改变首明文字节); Padding Oracle Attack(BLEHH): 逐字节猜测正确padding值(需知道有效/无效的区分方式)",
                    "  CTR模式: 流密码特性 — 密钥/IV重用导致 XOR(m1^m2)=c1^c2 可分离明文; IV预测/操控",
                    "  GCM模式: Nonce重用导致认证tag伪造; 认证标签长度不足时暴力破解",
                    "【阶段4: XOR/流密码攻击】",
                    "  已知明文: key[i] = ciphertext[i] ^ plaintext[i]; 用 flag{ 或已知头部恢复密钥流",
                    "  频率分析: 英文中空格(0x20)最频繁; 尝试单字节key(0-255)逐一测试看输出是否含 flag/ctf 关键字",
                    "  多次加密同一key: 若 key 长度短于明文则出现周期性; 用 Kasiski 测试或 Index of Coincidence 确定 key 长度后分组破解(Vigenere思路)",
                    "  RC4/LFSR: RC4的KSA/PRGA状态可逆; LFSR用 Berlekamp-Massy 从输出序列恢复反馈多项式",
                    "【阶段5: 哈希攻击】",
                    "  MD5/SHA1碰撞: HashPump工具实现长度扩展攻击(secret||data||padding) → secret||data||padding||append 的hash无需知道secret; MD5相同前缀碰撞(fastcoll/hashclash)",
                    "  弱哈希(短hash/可枚举): 彩虹表/字典攻击; salt太短可预计算",
                    "  自定义hash: 逆向hash函数逻辑; z3约束求解器自动寻找满足条件的输入",
                    "【阶段6: 数学/Z3求解】对于自定义加密/编码: 用 z3-solver 建立约束方程组自动求解未知变量(密钥/明文位); SageMath处理大数运算和数论问题(离散对数/椭圆曲线点阶); sympy符号推导简化复杂表达式",
                    "⚠️ 常见坑点预警:",
                    "  1. [RSA n分解失败] factordb查不到且本地工具跑不动 → 检查是否遗漏了题目给的 hint(部分p/q/phi/d的低位)；尝试 Coppersmith(已知n的部分高位/低位)或 Boneh-Durfee(d接近n^0.292)",
                    "  2. [e=3广播攻击条件不满足] m^e >= n 导致无法直接开根 → 题目可能需要用 Franklin-Reiter 相关消息攻击(Coppersmith short pad) 或检查是否有 oracle 泄露 msb/lsb",
                    "  3. [AES Padding Oracle误判] 修改密文后服务器返回统一错误信息 → 区分方式: 正确padding时响应慢(解密+验证耗时)，错误padding时立即返回；或观察响应长度差异",
                    "  4. [XOR key长度判断错误] 单字节key但用了多字节分析方法 → 先 IC(Index of Coincidence) 确认周期性，无周期则试单字节(0-255); 有 flag{ 头部可直接反推前5字节key",
                    "  5. [Hash长度扩展攻击secret过长] HashPump 要求知道 secret 长度但不要求内容 → 若不知道 secret_len 可逐个尝试常见值(10-50); 注意 padding 格式(sha1: \\x80 + \\x00*填充 + \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 + 64bit大端长度)",
                    "  6. [编码嵌套层数漏解] base64(hex(rot13(text))) 只解了一层就停 → 观察输出: 如果仍含非可打印字符或编码特征继续解码; CyberChef 的 Magic 功能自动检测链",
                    "  7. [z3超时/无解] 约束过多或变量域太大导致求解器卡死 → 缩小搜索空间(限制变量范围如 BitVec(8)); 分步求解(先求部分变量再代入); 改用暴力枚举(小域空间)",
                    "  8. [RSA公钥格式异常] PEM解析失败 → 可能是 DER 十六进制格式直接导入；或 n/e 藏在图片/音频隐写中；检查是否为多素数RSA(多个p相乘)",
                    "  9. [ECC曲线参数不标准] 非标准曲线无法用标准库 → 用 sage 自定义椭圆曲线 y^2 = x^3 + ax + b over GF(p); 注意点阶(order)可能含小因子(Pohlig-Hellman加速)",
                    "  10. [流密码IV/Nonce重用检测失败] 两组密文看似无关但 IV 相同 → XOR两组密文得到 m1^m2 (与key无关); 已知明文攻击恢复key流"
                ]
            ),
            "ctf-reverse": SkillProfile(
                name="ctf-reverse",
                description="逆向工程 - 二进制/APK/WASM/VM保护/混淆/加壳/固件等程序的静态分析与动态调试",
                category="reverse",
                keywords=[
                    "reverse", "re", "逆向", "逆向工程", "reverse engineering",
                    "elf", "pe", "mach-o", "exe", "dll", "so", "dylib",
                    "ida", "idapro", "ghidra", "radare2", "r2", "binary ninja",
                    "反编译", "decompile", "反汇编", "disassemble", "汇编", "assembly", "asm",
                    "obfuscation", "混淆", "ollvm", "控制流平坦化", "虚假控制流", "不透明谓词",
                    "vm", "虚拟机保护", "vmprotect", "vmp", "自定义字节码", "bytecode", "opcode",
                    "upx", "加壳", "脱壳", "unpacking", "packer", "aspack", "themida",
                    "apk", "dex", "smali", "frida", "xposed", "hook", "jni",
                    "wasm", "webassembly", "javascript obfuscation", "js混淆",
                    "android", "ios", "swift", "objective-c", "dart", "flutter",
                    ".net", "ilspy", "dnspy", "dotnet", "mono",
                    "debugging", "调试", "动态调试", "断点", "breakpoint", "trace",
                    "patch", "补丁", "patchelf", "修改跳转", "nop掉校验",
                    "sign验证", "签名校验", "anti-debug", "反调试", "ptrace", "is_debugger",
                    "字符串加密", "常量折叠", "API隐藏", "导入表加密"
                ],
                tools=["bash", "python", "read_file", "write_file"],
                examples=[
                    "一个ELF文件，需要逆向分析找到正确的输入",
                    "APK文件，需要分析Android应用的验证逻辑",
                    "加壳了UPX，需要脱壳后分析",
                    "自定义VM保护的二进制，需要理解 opcode",
                    "混淆严重的.NET程序"
                ],
                strategy=[
                    "【阶段1: 文件类型识别与基本信息收集】用 file 确定文件类型(ELF/PE/Mach-O/APK/DEx/MSIL/WASM); 用 strings 提取可见字符串(flag/input/password/wrong/correct/success/fail/error); 用 readelf/objdump 查看段/节/导入导出函数; UPX等常见壳用 upx -d 直接脱壳; 其他壳用 DIE(Detect It Easy)识别",
                    "【阶段2: 静态分析核心逻辑】",
                    "  入口定位: main/Wmain/WinMain/DllMain; Android的onCreate/onResume; Flutter的main(); WASM的_start/_initialize",
                    "  函数调用图: 从入口跟踪数据流 — 输入读取→变换/比较→分支判断(正确/错误); 重点标记: strcmp/memcmp/strcmpi/strncmp 等比较函数及其参数来源",
                    "  关键算法提取: 将核心变换逻辑(异或/移位/查表/置换/S-box)还原为等效Python代码; 记录每一步的常量和操作顺序",
                    "【阶段3: 反混淆策略】",
                    "  OLLVM控制流平坦化: 识别分发变量(dispatcher)和基本块集合; 还原真实控制流: 追踪dispatcher的switch-case将基本块按真实执行顺序重组; 工具: D810(去OLLVM插件)/IDAFlatDecompiler/手动分析",
                    "  虚假控制流: 识别不透明谓词(恒真/恒假条件); 条件常量折叠去除死分支; 追踪真实依赖链",
                    "  字符串加密: 定位解密函数(通常在程序初始化阶段批量调用); 在解密后下断点或Hook拦截明文字符串",
                    "  API动态解析: Hook GetProcAddress/LoadLibrary/dlsym 拦截运行时解析结果; 或从传入的hash值反推API名称",
                    "【阶段4: VM保护逆向】",
                    "  第一步: 定位VM解释器循环(通常是一个大的while/switch结构); 识别寄存器模型(通用寄存器数量/栈指针/指令指针)",
                    "  第二步: 提取opcode表: 每个case对应一条指令的处理逻辑; 记录 opcode编号 → 操作语义 映射",
                    "  第三步: 提取VM bytecode: 通常在.data/.rodata段; 写脚本解析bytecode序列",
                    "  第四步: 将bytecode翻译回原始逻辑: 逐条解释执行或编写反编译器",
                    "【阶段5: 动态调试验证】",
                    "  Linux ELF: gdb + gef/pwndbg; 关键断点设在: 输入函数返回后(查看buffer内容)、比较函数前(查看比较双方值)、变换函数出入口(跟踪每步变化)",
                    "  Android: Frida Hook关键native函数(Java层用Java.perform, Native层用Interceptor.attach); Xposed模块; objection交互式工具",
                    "  Windows PE: x64dbg/OllyDbg; 关注SEH/VEH异常处理; TLS回调",
                    "  反对抗: ptrace(PTRACE_TRACEME)防附加 — patch掉或用strace/ltrace绕过; 时间检测 — 快照回滚; isDebuggerPresent — 修改PEB标志位",
                    "【阶段6: 自动化脚本生成】将逆向得到的算法写成Python求解脚本: 输入变换的正向逻辑(用于验证); 如果是可逆变换写反向求解; 如果涉及约束用z3求解; 对抗Anti-debug时考虑纯静态方案(完全靠反编译推理)",
                    "⚠️ 常见坑点预警:",
                    "  1. [反编译结果不准确] IDA/Ghidra 的伪代码可能有误(尤其优化级别高的代码) → 关键逻辑必须对照汇编交叉验证；注意编译器优化导致的变量合并/死代码消除",
                    "  2. [OLLVM去混淆后仍无法阅读] 自动工具(D810)处理失败 → 手动追踪分发变量(dispatcher)的赋值路径，用脚本辅助重建CFG；关注真实基本块的条件依赖关系而非混淆后的虚假分支",
                    "  3. [动态调试被检测] 程序一运行就退出或行为异常 → 检测点: ptrace(PTRACE_TRACEME)/isDebuggerPresent/rdtsc时间差/proc/self/status TracerPid → patch掉或用 strace/ltrace 静态跟踪替代",
                    "  4. [UPX脱壳后仍异常] upx -d 脱壳后程序崩溃或功能缺失 → 可能是手动修改的 UPX(改了 section 名或加了额外段)；用 debugger 在 OEP(原始入口点) 处 dump 内存更可靠",
                    "  5. [APK抓不到包] Frida hook 无响应或 SSL Pinning 拦截 → Frida Server 版本必须与架构匹配(arm/arm64/x86); SSL Pinning 用 Frida 的 ssl-pinning-bypass 脚本; Xposed 需要 root + 正确框架版本",
                    "  6. [VM opcode映射错误] VM case 数量巨大且相似 → 先识别特殊opcode(HALT/JMP/CALL/RET)作为锚点; 用符号执行(angr)自动探索路径比手动分析更快; 注意 opcode 可能有加密(运行时解密)",
                    "  7. [.NET反编译丢失逻辑] dnspy/ilspy 反编译结果缺少部分方法体 → 可能是混淆器(NETConfuser/Eazfuscator)使用了动态方法或资源嵌入; 用 ILSpy debug 模式在内存中dump",
                    "  8. [算法还原方向搞反] 输入→输出的变换写成了正向但需要逆向求解 → 如果是线性操作(异或/加减/置换)可直接逆运算; 如果是哈希/压缩/截断则不可逆需暴力/z3",
                    "  9. [字符串加密导致无线索] 反编译中全是数字/乱码看不到有意义字符串 → 在解密函数处下断点(通常在main之前批量调用); 或用 IDA脚本扫描 XOR 循环模式批量解密 .rodata 段",
                    "  10. [架构不匹配] ARM/MIPS/RISC-V 二进制用了 x86 工具分析 → file 命令确认架构后选择对应工具链(objdump -m arm / r2 -a arm); 交叉编译环境(qemu-user)运行测试"
                ]
            ),
            "ctf-misc": SkillProfile(
                name="ctf-misc",
                description="杂项综合 - 隐写术/取证分析/编码转换/音频分析/图片处理/流量分析/游戏/misc jail等非常规题型",
                category="misc",
                keywords=[
                    "misc", "杂项", "综合",
                    "stego", "steganography", "隐写", "lsb", "最低有效位", "png隐写", "jpeg隐写",
                    "exif", "元数据", "metadata", "exiftool", "文件头", "文件尾", "魔术数字",
                    "forensics", "取证", "pcap", "wireshark", "tshark", "流量分析", "网络包",
                    "memory", "内存取证", "volatility", "dump", "memdump", "strings提取",
                    "image", "图片", "png", "jpg", "gif", "bmp", "svg", "宽高", "crc32", "像素",
                    "audio", "音频", "wav", "mp3", "频谱", "spectrogram", "摩尔斯电码", "dtmf",
                    "video", "视频", "帧提取", "ffmpeg",
                    "encode", "decode", "编码", "解码", "base64", "base32", "base16", "base58",
                    "url编码", "unicode", "utf-8", "gbk", "编码转换",
                    "压缩包", "zip", "rar", "7z", "伪加密", "明文攻击", "known plaintext", "zipcloak",
                    "qr", "二维码", "barcode", "条形码",
                    "disk", "磁盘镜像", "dd", "ext4", "ntfs", "fat32",
                    "log", "日志", "access_log", "error_log", "apache", "nginx",
                    "game", "游戏", "math", "数学", "logic", "逻辑", "puzzle", "谜题",
                    "oscillator", "信号", "rfid", "nfc", "蓝牙", "ble",
                    "docker", "容器逃逸", "kubernetes", "k8s", "rbac",
                    "git", "git log", "git diff", "stash", "reflog", "版本历史",
                    "sqlite", "数据库", "sqlite3"
                ],
                tools=["bash", "python", "read_file", "write_file", "download"],
                examples=[
                    "一张图片，看起来正常但可能有隐藏信息",
                    "一个pcap流量包，需要分析其中的通信内容",
                    "奇怪的编码文本，需要多层解码",
                    "压缩包有密码或者伪加密",
                    "音频文件中隐藏了信息"
                ],
                strategy=[
                    "【阶段1: 格式识别与表面信息提取】用 file 确认真实文件类型(可能扩展名造假); 用 exiftool 提取所有元数据(作者/时间/软件/注释/GPS坐标); 用 strings 提取可读文本(flag/base64/url/关键字); 用 binwalk -e 自动提取嵌入文件; 检查文件尾是否有多余数据(追加隐藏)",
                    "【阶段2: 图片隐写分析】",
                    "  PNG LSB隐写: 用 zsteg/stegsolve 逐位平面分析; R/G/B通道分别检查LSB 0-7 bit; 可能需要组合多个bit平面或特定通道",
                    "  JPEG隐写: JPHide/JPEG隐写用 stegdetect/stegbreak 检测和解密; DCT系数隐写需要频域分析",
                    "  宽高篡改: CRC32校验冲突 — 修改高度使图片显示不全但数据完整; 用脚本暴力枚举正确高度",
                    "  PNG IDAT/ICCP/IEND段: 多余chunk可能藏数据; IEND后追加数据; IDAT中的filter byte manipulation",
                    "  Exif/Comment: EXIF Comment字段/PNG tEXt/iTXt/zTXt chunk存储数据",
                    "【阶段3: 音频隐写与信号分析】",
                    "  频谱图: 用 Audacity/Sonic Visualiser 打开查看频谱; 常见: 摩尔斯电码(长短波纹)、文字图形(波形画出字母)、DTMF拨号音",
                    "  LSB音频隐写: wav文件样本值的最低位; 用 deepsound/stegolsb 工具提取",
                    "  静音间隔: 长短静音编码二进制(长=1,短=0)",
                    "  频率调制: 不同频率代表不同含义(SSTV慢扫描电视图像传输)",
                    "【阶段4: 流量包分析(pcap)】",
                    "  用 wireshark/tshark 过滤: http/tcp/udp/icmp/dns/ftp; 追踪TCP流(Follow TCP Stream)还原HTTP会话",
                    "  提取对象: File → Export Objects → HTTP/TFTP/DNS等批量导出传输文件",
                    "  协议细节: DNS查询域名可能藏信息(子域名字符拼接); ICMP payload长度/数据藏数据; HTTP User-Agent/Cookie/参数藏flag",
                    "  加密流量: 看TLS Client Hello中的SNI/证书; 非标准端口可能非HTTPS; USB流量用usbcap dissectors",
                    "【阶段5: 压缩包与密码】",
                    "  伪加密: ZIP的全局加密标志位(09/00改为00/00) — 手动修复; RAR同样原理",
                    "  明文攻击(pkzip): 已知压缩包内某文件的完整明文 → 用 bkcrack 恢复密钥 → 解密其他文件",
                    "  爆破: fcrackzip/john/rar2john+john; 常见弱口旗: 00000000/12345678/password/admin",
                    "  分卷压缩: .z01/.z02/.../.zip 合并后解压; 嵌套压缩(套娃)逐层解压注意文件名/注释线索",
                    "  特殊格式: ACE/7z/TAR.GZ/BZIP2 各自的工具链",
                    "【阶段6: 多层编码解码】",
                    "  常见编码链识别: 先看特征(base64有+=/; base32全大写+A-Z2-7=; hex是0-9a-f; URL编码%; Unicode有\\uXXXX)",
                    "  自动化: CyberChef Recipe链(From Base64 → From Hex → Reverse等组合); Python codecs库",
                    "  注意: 编码可能嵌套(如 base64(hex(rot13(text)))) ; 也可能与简单加密结合(XOR+Base64)",
                    "  取证线索: Git仓库用 git log/git diff/git reflog 查看历史提交和暂存变更; SQLite数据库可直接sql查询",
                    "【阶段7: 杂项特殊题型】",
                    "  游戏题: 分析游戏规则找规律/作弊点; 内存搜索flag值(CE修改器思路); 协议逆向(抓包分析游戏通信)",
                    "  数学/逻辑题: 数论(欧拉函数/中国剩余定理/二次剩余); 组合排列; 图论; 用Python/sage/z3求解",
                    "  IoT/硬件: RFID/NFC数据解析; 固件binwalk提取; 串口通信分析(baud rate检测)",
                    "  容器安全: Docker逃逸(--privileged/挂载socket/内核漏洞); K8s RBAC滥用; 云环境元数据(169.254.169.254)",
                    "⚠️ 常见坑点预警:",
                    "  1. [LSB隐写工具无输出] zsteg/stegsolve 跑完什么都没发现 → 尝试: 组合不同通道(R+G+B的LSB0-7两两XOR); 检查 alpha 通道; 用 PIL 脚本逐像素手动提取; 可能是 MSB(最高有效位)而非 LSB",
                    "  2. [宽高CRC修改后图片打不开] 暴力枚举高度值后图片损坏 → CRC32只校验前14字节(IHDR)，高度改错会导致数据偏移；正确做法: 固定宽度，遍历高度直到 IHDR 的 CRC32 匹配",
                    "  3. [pcap过滤条件太窄] 只看了 HTTP 流量没找到 flag → 扩展到: DNS(A记录/CNAME可能藏hex)、ICMP(payload data)、USBHID(键盘输入)、ARP/DHCP、非标准端口的大包; tshark -T fields -e data 提取原始payload",
                    "  4. [压缩包密码爆破卡住] john/fcrackzip 跑了很久没结果 → 先检查: 是否伪加密(全局标志位09→00); 文件名/注释是否藏了密码提示; 是否有明文文件可用 bkcrack; 密码可能是 flag 本身或题目名称",
                    "  5. [编码解码死循环] base64 解码后还是乱码 → 可能是: 自定义 base64 字符表(非标准ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/); 多层嵌套(base64→hex→base64...); 编码和加密混合(XOR 后再 base64)",
                    "  6. [音频分析工具选择错误] Audacity 看不到隐含信息 → 尝试 Sonic Visualiser(更多频谱层选项); DeepSound(音频 LSB); silenteye(静音间隔); DTMF 用在线 DTMF 解码器; SSTV 用 QSSTV 或 RX-SSTV",
                    "  7. [binwalk提取为空] binwalk -e 没结果 → 手动检查: dd if=file bs=1 skip=N (从某偏移开始); strings 搜索 PK/\\x50\\x4b(ZIP)/Rar!(RAR)/\\x89PNG; 文件末尾追加数据(file size > 实际内容大小)",
                    "  8. [二维码无法识别] 二维码图片残缺或模糊 → 尝试: 在线修复工具( QBH repair / 在线 QR decode); 手动定位 finder pattern(三个回字角) 后用 zbarimg 强制解码; 数据可能在多个二维码中拼接",
                    "  9. [Git历史为空] git log 无提交记录 → 检查: git reflog(被 reset --hard 丢弃的提交); git stash list(暂存的更改); .git/objects 直接搜索(git cat-file -p 每个object); dangling objects(git fsck --lost-found)",
                    "  10. [容器逃逸环境差异] 题目给的 Docker 环境与本地测试不一致 → 注意: /proc/1/cgroup 判断是否为容器; 挂载的 socket(/var/run/docker.sock)权限; 内核版本(uname -r)决定漏洞利用可行性; cap_capable 检查"
                ]
            ),
            "ctf-forensics": SkillProfile(
                name="ctf-forensics",
                description="数字取证 - 内存镜像分析/磁盘取证/日志分析/恶意软件分析/网络取证等电子证据调查技术",
                category="forensics",
                keywords=[
                    "forensics", "取证", "digital forensics", "电子取证",
                    "memory", "内存", "ram", "memdump", "raw", "vmem",
                    "volatility", "vol3", "内存分析", "进程列表", "网络连接", "命令历史",
                    "registry", "注册表", "hive", "ntuser.dat", "software", "system",
                    "disk", "磁盘", "分区表", "mbr", "gpt", "引导扇区",
                    "deleted", "已删除", "恢复", "recover", "undelete", "slack space",
                    "timeline", "时间线", "mtime", "atime", "ctime", "mac时间",
                    "malware", "恶意软件", "病毒", "trojan", "ransomware", "勒索",
                    "yara", "特征匹配", "ioc", "威胁指标",
                    "email", "邮件头", "mime", "smtp", "pop3", "imap",
                    "browser", "浏览器历史", "cookie", "缓存", "书签", "下载记录",
                    "swap", "pagefile", "hibernate", "休眠文件", "页面文件"
                ],
                tools=["bash", "python", "read_file", "write_file"],
                examples=[
                    "一个内存镜像文件，需要分析其中的活动进程",
                    "磁盘镜像，需要恢复被删除的文件",
                    "Windows注册表导出文件，寻找可疑痕迹",
                    "恶意软件样本分析"
                ],
                strategy=[
                    "【阶段1: 内存镜像分析(volatility3)】",
                    "  基本信息: windows.info / linux.pslist 确认OS版本和进程列表",
                    "  进程深入: windows.pstree(进程树)/windows.cmdline(命令行参数)/windows.envars(环境变量)",
                    "  网络活动: windows.netscan(TCP连接)/windows.netstat(监听端口)/windows.dns_cache(DNS缓存)",
                    "  命令历史: windows.cmdline / linux.bash(终端命令历史)",
                    "  提取文件: windows.filescan(文件对象列表) → windows.dumpfile(按offset导出); linux.elist_files → linux.dump_file",
                    "  密码/凭证: windows.hashdump(SAM哈希)/linux.bash(环境变量中的密码)/windows.lsadump(LSA secrets)",
                    "  恶意代码: windows.malfind(注入的可执行代码区域)/windows.modules(加载的DLL)",
                    "【阶段2: 磁盘取证】",
                    "  分区识别: mmls/parted列出分区表; fsstat确认文件系统类型(ext4/ntfs/fat32)",
                    "  文件恢复: fls列出文件(含删除); icat按inode恢复文件内容; recoverjpeg从未分配空间恢复图片",
                    "  元数据: istat查看inode详细信息(时间戳/大小/块指针); 时间线用 bodyfile + mactime 重建",
                    "  未分配空间: dls/dcat读取; slack space(簇内尾部空间)可能残留旧数据",
                    "  注册表(Windows): rip.pl(registry infinite parser) 或 regripper 解析 hive 文件; 重点: Run键(自启动)/RecentDocs(最近文档)/UserAssist(程序使用记录)/Shellbags(文件夹访问记录)/USB设备记录",
                    "【阶段3: 日志与时间线构建】",
                    "  Windows Event Log: wevtutil 解析.evtx; Security日志(4624登录/4688进程创建/4663文件访问); System日志(7036服务变化/6008关机)",
                    "  Web日志: Apache access.log(NCSA格式); Nginx访问日志; 分析: IP聚合/路径统计/异常User-Agent/SQL注入特征/路径穿越尝试",
                    "  时间线排序: log2timeline(plaso) 或 mactime(bodyfile) 按MAC时间排序; 寻找: 异常时间段的活动/启动-感染-清除的时间关系",
                    "【阶段4: 恶意软件基础分析】",
                    "  静态: strings提取URL/IP/域名/注册表路径/文件路径; import表分析(可疑DLL/API); 资源段(嵌入的PE/脚本/数据)",
                    "  行为: sandbox执行(Cuckoo/Any.Run); 监控: 文件系统改动/注册表修改/网络连接/进程创建",
                    "  YARA: 编写规则匹配恶意特征家族; VirusTotal/ Hybrid Analysis 在线辅助",
                    "⚠️ 常见坑点预警:",
                    "  1. [volatility版本不匹配] vol2/vol3 配置文件(profile)不兼容 → 确认镜像OS版本后用正确的 symbol table: linux(下载对应内核 dwarf 文件); windows(用 --kaddr 或自动检测); 若 vol3 无 profile 可尝试 vol2 兼容模式",
                    "  2. [内存镜像格式识别错误] raw/vmem/mem/ img 后缀但实际格式不同 → 用 file + strings(前100行)判断: raw=裸内存; vmem=VMware; mem=Windows hibernation/Ethereal; img=E01/ AFF4 格式需用 libewf 工具",
                    "  3. [进程已退出找不到痕迹] 目标进程在 dump 时已终止 → 检查: 进程对象仍在 pool 中(vol3 的 pcsxscan); 命令行参数残留在 PEB 中; 网络连接可能还在 TIME_WAIT 状态(netscan); 文件句柄未关闭(filescan)",
                    "  4. [磁盘分区表损坏] mmls 无法列出分区 → 可能是: 软RAID(mdadm); LVM逻辑卷(lvm_scan); GPT备份表受损(用 gpt_fix); 直接用 fsstat 尝试从偏移量扫描文件系统签名(\\x53\\xEF for ext4 / NTFS for ntfs)",
                    "  5. [注册表hive无法解析] regripper 报错或输出为空 → 检查 hive 类型(SYSTEM/SAM/SOFTWARE/NTUSER.DAT/SECURITY); SYSTEM hive 需要 bootkey 解密 SAM; NTUSER.DAT 是用户配置非系统级; 用 rip.exe 替代 regripper",
                    "  6. [时间线时间戳混乱] 不同文件系统的 MAC 时间精度不同 → FAT32 只有 2 秒精度; NTFS 记录到 100ns; 注意时区差异(UTC vs 本地时间); mactime 输出注意 --b 参数(body file 格式)",
                    "  7. [evtx日志被清除] Security.evtx 为空或只有启动记录 → 检查: Windows Event Log 备份(.evt 扩展名); %SystemRoot%\\System32\\winevt\\Logs 目录下是否有归档; 用 EvtxECmd (Kroll Parser) 从 unallocated space 恢复",
                    "  8. [YARA规则无匹配] 自定义规则扫不到恶意代码 → 原因: 样本被打包/加壳(先脱壳再扫); 规则条件太严格(放宽字符串匹配用 nocase/fullword); 恶意代码在内存中解压(malfind 提取后扫描)",
                    "  9. [swap/pagefile分析遗漏] 只分析了内存镜像忽略了交换文件 → pagefile.sys/swapfile/hiberfil.sys 可能包含被换出的敏感数据(密码/密钥/完整文件); 用 volatility 的 swap解析模块或 strings + grep 关键字",
                    "  10. [证据链完整性忽略] 取证过程未记录哈希 → 对每个提取的文件计算 SHA256 并记录来源(offset/inode); 最终报告必须包含: 原始镜像哈希、操作步骤日志、提取物哈希链，否则证据不可信"
                ]
            )
        }

    def detect_skills(self, task_description: str, context: str = "") -> List[SkillProfile]:
        text = f"{task_description}\n{context}".lower()
        scored: List[Tuple[int, SkillProfile]] = []

        for profile in self.skills.values():
            score = sum(1 for kw in profile.keywords if re.search(re.escape(kw.lower()), text))
            if score > 0:
                scored.append((score, profile))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [profile for _, profile in scored[:3]]

    def get_skills_by_names(self, names: List[str]) -> Tuple[List[SkillProfile], List[str]]:
        profiles: List[SkillProfile] = []
        unknown: List[str] = []
        seen = set()

        alias_map = {
            "pwn": "ctf-pwn", "binary": "ctf-pwn", "elf": "ctf-pwn",
            "web": "ctf-web", "sqli": "ctf-web", "xss": "ctf-web", "ssti": "ctf-web",
            "crypto": "ctf-crypto", "rsa": "ctf-crypto", "xor": "ctf-crypto",
            "reverse": "ctf-reverse", "re": "ctf-reverse", "ida": "ctf-reverse",
            "misc": "ctf-misc", "stego": "ctf-misc", "encode": "ctf-misc",
            "forensics": "ctf-forensics", "pcap": "ctf-forensics",
        }

        for raw_name in names:
            name = raw_name.strip().lower()
            if not name:
                continue
            if name in seen:
                continue
            seen.add(name)

            resolved = alias_map.get(name, name)
            profile = self.skills.get(resolved)
            if profile:
                profiles.append(profile)
            elif resolved in self.skills:
                profiles.append(self.skills[resolved])
            else:
                unknown.append(name)

        return profiles, unknown

    def render_skill_prompt(self, profiles: List[SkillProfile]) -> str:
        if not profiles:
            return ""

        lines = [
            "## 已激活技能画像",
            "以下技能根据题目描述自动匹配，解题时必须严格遵循对应策略步骤：",
            "",
        ]

        for profile in profiles:
            lines.append(f"### {profile.name} ({profile.category})")
            lines.append(f"**说明**: {profile.description}")
            lines.append("")
            lines.append("**核心策略（必须按顺序执行）**: ")
            for i, step in enumerate(profile.strategy, 1):
                lines.append(f"  {i}. {step}")
            if profile.tools:
                lines.append(f"**推荐工具**: {', '.join(profile.tools)}")
            lines.append("")

        lines.append("---")
        lines.append("**强制要求**:")
        lines.append("- Thought 中必须声明当前使用哪个 Skill 及所处阶段")
        lines.append("- ret2libc 类题目必须严格按「信息收集→偏移计算→泄漏libc→构造ROP」原子步骤执行")
        lines.append("- Web 注入类题目必须先完成「指纹识别→输入点枚举→WAF检测」再进行利用")
        lines.append("- 发现 Flag 后立即用 `final:` 提交")

        return "\n".join(lines)
