این پروژه برای مبارزه با تجزیه و تحلیل پروتکل DPI و دور زدن انسداد پروتکل در نظر گرفته شده است.

یکی از راه های ممکن برای غلبه بر تجزیه و تحلیل امضای DPI ، اصلاح پروتکل است.
سریعترین اما آسان ترین راه اصلاح خود نرم افزار نیست.
برای TCP ، obfsproxy وجود دارد. با این حال ، در مورد VPN ، تنها راه حل های خیلی سریع (openvpn) روی TCP کار نمی کنند.

در مورد upp چه باید کرد؟
اگر هر دو انتها در یک آدرس IP خارجی قرار داشته باشند ، امکان تغییر بسته ها در سطح IP وجود دارد.
به عنوان مثال ، اگر SMV دارید و یک روتر بازکن در خانه و یک آدرس IP خارجی از ISP دارید ،
سپس می توانید از این تکنیک استفاده کنید اگر یک نقطه پایانی در پشت NAT باشد ، امکانات محدود هستند ،
اما لمس کردن عناوین udp / tcp و بارهای ممکن هنوز امکان پذیر است.

طرح به شرح زیر است:
 همتای 1 <=> obfuscator / deobfuscator IP <=> شبکه <=> obfuscator / deobfuscator IP <=> همتای 2

برای بسته بندی از همسال 1 به همسال 2 ، که هر دو دارای آدرس IP خارجی هستند ،
فقط باید هدر های IP مناسب داشته باشید. می توانید هر شماره پروتکل را تنظیم کنید ، بار IP را مخفی یا رمزگذاری کنید ،
از جمله هدرهای tcp / udp. DPI نخواهد فهمید که چیست.
او پروتکل های IP غیر استاندارد با محتوای ناشناخته را مشاهده می کند.
ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid
ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid


ipobfs
------

کنترل کننده صف NFQUEUE ، IP خراب کننده / قطع کننده IP.

 --qnum = <nfqueue_number>
 - دزد؛ daemonize
 --pidfile = <filename>؛ ارسال pid به پرونده
 --user = <username>؛ خصوصیات ریشه را رها کنید
 - گول زدن؛ اطلاعات اشکال زدایی را چاپ کنید
 --uid = uid [: gid]؛ خصوصیات ریشه را رها کنید
 --ipproto-xor = 0..255 | 0x00-0xFF؛ شناسه پروتکل xor با مقدار داده شده
 --data-xor = 0xDEADBEAF؛ x IP payload (بعد از هدر IP) با مقدار HEX 32 بیتی
 --data-xor-offset = <position>؛ در حالت مشخص شده شروع به xoring کنید
 --data-xor-len = <bytes>؛ طول xor حداکثر بسته بندی xor پس از جبران اگر مشخص نشده باشد
 --csum = هیچ | رفع | معتبر؛ چک هدر حمل و نقل: هیچ کدام = لمس آن ، رفع = نادیده گرفتن چک روی بسته های ورودی ، معتبر است = همیشه چک را معتبر کنید
ipobfs
------

کنترل کننده صف NFQUEUE ، IP خراب کننده / قطع کننده IP.

 --qnum = <nfqueue_number>
 - دزد؛ daemonize
 --pidfile = <filename>؛ ارسال pid به پرونده
 --user = <username>؛ خصوصیات ریشه را رها کنید
 - گول زدن؛ اطلاعات اشکال زدایی را چاپ کنید
 --uid = uid [: gid]؛ خصوصیات ریشه را رها کنید
 --ipproto-xor = 0..255 | 0x00-0xFF؛ شناسه پروتکل xor با مقدار داده شده
 --data-xor = 0xDEADBEAF؛ x IP payload (بعد از هدر IP) با مقدار HEX 32 بیتی
 --data-xor-offset = <position>؛ در حالت مشخص شده شروع به xoring کنید
 --data-xor-len = <bytes>؛ طول xor حداکثر بسته بندی xor پس از جبران اگر مشخص نشده باشد
 --csum = هیچ | رفع | معتبر؛ چک هدر حمل و نقل: هیچ کدام = لمس آن ، رفع = نادیده گرفتن چک روی بسته های ورودی ، معتبر است = همیشه چک را معتبر کنید
 
از آنجایی که عملکرد XOR متقارن است ، همان پارامترها برای انسداد کننده و دفع کننده تعریف می شوند.
از هر طرف نمونه ای از برنامه راه اندازی می شود.

فیلتر کردن بسته های خروجی آسان است زیرا آنها باز هستند. با این حال ، مقدار مشخصی از u32 برای پیام های دریافتی مورد نیاز است.
شماره پروتکل ("-p") در فیلتر نتیجه xor پروتکل اصلی با ipproto-xor است.
سرور ipv4 udp: 16:
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 -u32 "0 >> 22 & 0x3C @ 0 & 0xFFFF = 16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp -sport 16 -j NFQUEUE -queue-num 300-round-bypass
client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16  -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=128 --data-xor=0x458A2ECD --data-xor-offset=4 --data-xor-len=44


چرا data-xor-offset = 4: هدرهای پروتکل TCP و UDP با شماره پورت منبع و مقصد شروع می شوند که هر یک از آنها 2 بایت است.
برای آسانتر نوشتن در u32 ، شماره های پورت را لمس نکنید. می توانید لمس کنید ، اما بعد باید درک کنید که در چه چیزی است
پورت های اصلی تغییر خواهند یافت و این مقادیر را در u32 می نویسند.
چرا data-xor-len = 44: نمونه ای برای محافظ سیم آورده شده است. 44 بایت برای XOR هدر udp و تمام هدرهای Wireguard کافی است.
سپس داده های سیم کشی رمزگذاری شده را بیاورید ، که هیچ مفهومی از XOR ندارد.

شما حتی می توانید udp را با ipproto-xor = 23 به "tcp trash" تبدیل کنید. طبق گفته هدر ip ، این در مورد tcp است ، اما به جای هدر tcp ، بی فایده است.
از طرف دیگر ، چنین بسته هایی می توانند از طریق جعبه های متوسط ​​بگذرند و کنترل آن می تواند دیوانه شود.
از طرف دیگر ، حتی می تواند خوب باشد.

من
