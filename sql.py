# 数据库导出的 sql 文件处理脚本
sqls = []

# 读取文件按行处理
with open('your_file.txt', 'r') as file:
    for line in file:
        # 处理双引号转义

        # 处理反斜杠转义
        line = line.replace('\\', '\\\\')
        line = line.replace('"', '\\"')

        # 将处理后的内容插入到 sqls 中
        sqls.append(f'sqls.add("{line.strip()}");')

if __name__ == '__main__':
    # 打印结果
    for sql in sqls:
        print(sql)
