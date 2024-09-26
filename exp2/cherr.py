from bs4 import BeautifulSoup
import requests
import re
import json
import os
import time

MAX_PAGE = 100
MAX_DEPTH = 5



def write_to_file(res,file_name='result.json'):
    with open(file_name, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)


def get_html(url):
    # 睡眠一段时间，防止被封
    time.sleep(5)
    try:
        header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/"
                  "537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"}
        r = requests.get(url, headers=header,timeout=30)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        print(r)
        return r.text
    except:
        return " ERROR "

def parse_page(html):
    soup = BeautifulSoup(html, 'html.parser')
    # 保存返回结果的json 对象 res
    res = {}
    # class="yahei newstittle" 为标题 放入 res.title
    res['title'] = soup.find('p', class_='yahei newstittle').get_text()
    # class="news" 为新闻内容 放入 res.content 只放入文字内容,去掉其中类似“\n\n\u3000\u3000”的字符
    content = soup.find('div', class_='news').get_text()
    content= re.sub(r'[\n\u3000]', '', content)
    res['content'] = content
    
    # class="cms_block_span" 为推荐链接，解析其中所有的 href 放入 res.links
    right_content=soup.find('div', class_='float_right main_r')
    link_content=right_content.find('span', class_='cms_block_span')
    print(link_content)
    # 单独解析link_content中的所有链接
    links = link_content.find_all('a')
    res['links'] = []
    for link in links:
        # 加上https: 使得链接完整
        res['links'].append(link['href'].replace('//','https://'))
    
    return res
        
        
def parse_page_cherr(html):
    soup = BeautifulSoup(html, 'html.parser')
    print(html)
    # 保存返回结果的json 对象 res
    res = {}
    res['title'] = soup.find('h1').get_text()
    # class="news" 为新闻内容 放入 res.content 只放入文字内容,去掉其中类似“\n\n\u3000\u3000”的字符
    contents = soup.find_all('p')
    content = ''
    for c in contents:
        content += c.get_text()
        
    res['content'] = content

    links = soup.find_all('a')
    res['links'] = []
    for link in links:
        # 加上https: 使得链接完整
        res['links'].append(link['href'])
    
    return res
        
def BFS(url):
    res_total = []
    cnt = 0 
    depth = 0
    try:
        
        # 用一个队列来保存当前层的所有url
        queue = []
        # 用一个集合来保存已经访问过的url
        visited = set()
        # 用一个集合来保存所有的url
        all_urls = set()
        # 将初始url放入队列
        queue.append(url)
        # 将初始url放入已访问集合
        visited.add(url)
        # 将初始url放入所有url集合
        all_urls.add(url)
        # 用于保存结果
        res = []
        # 当层数不超过max时
        while depth < MAX_DEPTH:
            # 当队列不为空时
            while queue:
                # 取出队列的第一个元素
                url = queue.pop(0)
                print(url)
                # res=parse_page(get_html(url))
                res=parse_page(get_html(url))
                res_total.append(res)
                cnt+=1
                if cnt>=MAX_PAGE:
                    return res_total
                # 将当前页面的所有url放入队列
                for link in res['links']:
                    if link not in visited:
                        queue.append(link)
                        visited.add(link)
                        all_urls.add(link)
            # 深度加一
            depth += 1
        return res_total
    except Exception as e:
        print(e)
        return res_total
        

def DFS(url):
    res_total = []
    cnt = 0 
    depth = 0
    try:
        
        # 用一个栈来保存当前层的所有url
        stack = []
        # 用一个集合来保存已经访问过的url
        visited = set()
        # 用一个集合来保存所有的url
        all_urls = set()
        # 将初始url放入栈
        stack.append(url)
        # 将初始url放入已访问集合
        visited.add(url)
        # 将初始url放入所有url集合
        all_urls.add(url)
        # 用于保存结果
        res = []
        # 当层数不超过max时
        while depth < MAX_DEPTH:
            # 当栈不为空时
            while stack:
                # 取出栈的第一个元素
                url = stack.pop()
                print(url)
                # res=parse_page(get_html(url))
                res=parse_page(get_html(url))
                res_total.append(res)
                cnt+=1
                if cnt>=MAX_PAGE:
                    return res_total
                # 将当前页面的所有url放入栈
                for link in res['links']:
                    if link not in visited:
                        stack.append(link)
                        visited.add(link)
                        all_urls.add(link)
            # 深度加一
            depth += 1
        return res_total
    except Exception as e:
        print(e)
        return res_total


def main():
    url = 'https://comment.lnd.com.cn/system/2024/08/07/030477959.shtml'
    # url = 'http://pubserver.cherr.cc/index.html'
    # url = 'https://cherr.cc'
    
    # print(get_html(url))
    

    
    bfs_res=BFS(url)
    write_to_file(bfs_res,"BFS.json")
    dfs_res=DFS(url)
    write_to_file(dfs_res,"DFS.json")
    
        

if __name__ == '__main__':
    main()