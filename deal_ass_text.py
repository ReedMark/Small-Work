# -*- coding: UTF-8 -*-


f_s = open('D:/save.ass', 'w+', encoding='UTF-8')
with open('D:/The Real Meaning of Life.ass', 'r+', encoding='UTF-8') as f:
    lines = f.readlines()
    for line in lines:
        if line[:8] != 'Dialogue':
            f_s.write(line)
        if line[:8] == 'Dialogue':
            if "120,120" in line:
                f_s.write(line)
                # print(line)
    f.close()
f_f = open('D:/save_final.ass', 'w+', encoding='UTF-8')
with open('D:/save.ass', 'r+', encoding='UTF-8') as f_t:
    lines = f_t.readlines()
    pre_index = 0
    for index, line in enumerate(lines):
        if line[:8] != 'Dialogue':
                f_f.write(line)
        if line[:8] == 'Dialogue':
            if '英' in line:
                min_index = index - pre_index
                pre_index = index
                if min_index == 1:
                    print(lines[index])
                    f_f.write(lines[index])
            if '中' in line:
                f_f.write(lines[index])