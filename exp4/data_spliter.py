# coding=utf-8

import sys
import random

if __name__ == '__main__':

    inputFile = 'data/data.txt'
    rate = 0.8 # 一般机器学习走0.8最好
    trainOut = 'data/train.txt'
    testOut = 'data/test.txt'

    with open(inputFile, 'r', encoding='utf-8', errors='ignore') as fin, \
            open(trainOut, 'w', encoding='utf-8') as fTrain, \
            open(testOut, 'w', encoding='utf-8') as fTest:
        for line in fin:
            curRandom = random.random()
            if (curRandom <= rate):
                fTrain.write(line)
            else:
                fTest.write(line)
    print('split OK')
