import os
import uuid
import random
import string
import datetime


# 定义更多常见的英语单词
nouns = ["dog", "cat", "house", "tree", "car", "book", "apple", "sun", "moon", "river", "flower", "bird", "mountain", "ocean", "city", "school", "family", "friend", "teacher", "student"]
verbs = ["run", "jump", "play", "eat", "sleep", "sing", "dance", "read", "write", "talk", "walk", "swim", "fly", "climb", "cook", "draw", "paint", "study", "work", "laugh"]
adjectives = ["big", "small", "red", "blue", "green", "happy", "sad", "funny", "beautiful", "ugly", "tall", "short", "old", "young", "smart", "kind", "brave", "curious", "lazy", "hungry"]
adverbs = ["quickly", "slowly", "carefully", "happily", "sadly", "loudly", "quietly", "well", "badly", "often", "always", "never", "sometimes", "usually", "suddenly", "gently", "eagerly", "patiently"]
prepositions = ["in", "on", "under", "over", "by", "with", "for", "to", "from", "at", "behind", "beside", "between", "through", "around", "upon", "into", "onto", "towards", "across"]
locations = ["the park", "the garden", "the beach", "the forest", "the playground", "the library", "the office", "the kitchen", "the bedroom", "the living room"]
# 定义一个函数来生成随机句子
def generate_sentence():
    # 随机选择一个主语
    subject = random.choice(nouns).capitalize()

    # 随机选择一个动词
    verb = random.choice(verbs)

    # 随机选择一个宾语
    object_noun = random.choice(nouns)

    # 随机选择一个形容词
    adjective = random.choice(adjectives)

    # 随机选择一个副词
    adverb = random.choice(adverbs)

    # 随机选择一个介词和名词短语
    preposition = random.choice(prepositions)
    location_noun = random.choice(nouns)
    location = f"{preposition} the {location_noun}"

    # 组合成一个完整的句子
    sentence = f"{subject} {adverb} {verb} the {adjective} {object_noun} {location}."

    return sentence




# 设置生成的 HTML file 数量
num_files = 1000

# 清空输出目录
if os.path.exists("output"):
    for file in os.listdir("output"):
        os.remove(os.path.join("output", file))

# 创建输出目录
output_dir = "output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# 存储已生成的文件名
file_names = []

# 生成 HTML 文件
for _ in range(num_files):
    file_name = f"{uuid.uuid4().hex}.html"
    file_path = os.path.join(output_dir, file_name)
    file_names.append(file_name)

    # 生成随机标题和内容
    title = generate_sentence()
    content = '\n\n'.join(["<p>"+generate_sentence()+"</p>" for _ in range(random.randint(3, 10))])
    # 生成随机链接
    links = random.sample(file_names, min(random.randint(2, 5), len(file_names)))

    # 构建 HTML 内容
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
    </head>
    <body>
        <h1>{title}</h1>
        <div>
        {content}
        </div>
        <h2>Links:</h2>
        <ul>
    """
    for link in links:
        html += f"        <li><a href='http://pubserver.cherr.cc/{link}' class='links'>{link}</a></li>\n"
    html += """    </ul>\n
    <div>Powered By Cherr & HITLUG</div>
    </body>\n</html>"""

    # 写入 HTML 文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html)

# 检查并修复未被链接的文件
for file_name in file_names:
    file_path = os.path.join(output_dir, file_name)
    with open(file_path, 'r', encoding='utf-8') as f:
        html = f.read()
    if file_name not in html:
        # 随机选择一个文件并添加链接
        link_file = random.choice(file_names)
        html = html.replace('</ul>', f"        <li><a href='http://pubserver.cherr.cc/{link_file}' class='links'>{link_file}</a></li>\n    </ul>")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)

# 删除第一个文件的链接，因为他只指向了自己
with open(os.path.join(output_dir, file_names[0]), 'r', encoding='utf-8') as f:
    html = f.read()

# 生成一个 index.html 文件 随机指向几个文件
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Index</title>
</head>
<body>
    <h1>这是一个索引页</h1>
    <p>一束光照亮了上帝，以为是信仰，没想到是我捏的闪</p>
    <h2>Links:</h2>
    <ul>
"""
for link in random.sample(file_names[1:], min(5, len(file_names) - 1)):
    html += f"        <li><a class='links' href='http://pubserver.cherr.cc/{link}'>{link}</a></li>\n"
html += "    </ul>\n<div>Powered By Cherr & HITLUG</div>\n</body>\n</html>"

# 写入 index.html 文件
with open(os.path.join(output_dir, "index.html"), 'w', encoding='utf-8') as f:
    f.write(html)

print(file_names)
    

print(f"已生成 {num_files} 个 HTML 文件,保存在 {output_dir} 目录下。")
