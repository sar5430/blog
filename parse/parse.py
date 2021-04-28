import os
import datetime
from markdown import markdown

header_template = '''
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <title>sar's blog</title>

        <link href="/style/style.css" rel="stylesheet" />

    </head>

    <body>

        <h1>sar's blog</h1>
        <hr>
        <a href="/">Home</a>
        <hr>
'''

footer_template = '''
        
        <hr>
        <a href="https://twitter.com/sar5430">Twitter</a> - 
        <a href="https://github.com/sar5430">Github</a> - 
        <a href="https://discord.com/">Discord:</a> sar#5430 -
        Visit <a href="https://crackmes.one/">Crackmes.one</a>!
    </body>
</html>
    '''


def build_page(filename, content):
    OUTDIR = "../p/"
    page = header_template + content + footer_template
    _, tail = os.path.split(filename)
    filename_no_md = tail.split(".")[0]

    out = open(OUTDIR + filename_no_md + ".html", "w")
    out.write(page)

def generate_html_from_post(filename):
    f = open(filename, "r")
    content = f.read()
    content_html = markdown(content, extensions=["fenced_code", "tables"])
    build_page(filename, content_html)

def build_index(files):
    OUTDIR = "../"
    posts = {}

    for filename in files:
        _, tail = os.path.split(filename)
        date_str = tail.split(".")[0][0:10]
        title = tail.split(".")[0][11:]
        date_time_obj = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        posts[date_time_obj] = title

    dict_items = posts.items()
    sorted_items = sorted(dict_items, reverse=True)

    content = header_template
    for item in sorted_items:
        content += "<b>[" + item[0].strftime("%Y/%m/%d") + "]</b>:<a href=\"./p/" + item[0].strftime("%Y-%m-%d") + "-" + item[1] + ".html\">" + item[1].replace("_", " ") + "</a></br>"
    content += footer_template

    out = open(OUTDIR + "index.html", "w")
    out.write(content)


def loop_files():
    DIR = "../posts/"
    files = os.listdir(DIR)
    for f in files:
        generate_html_from_post(DIR + f)
    build_index(files)

os.chdir(os.path.dirname(os.path.realpath(__file__)))
loop_files()


