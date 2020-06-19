#!/usr/bin/python3

import os
import struct
import sys
from ctypes import *
import statistics

class Metadata(Structure):
    _fields_ = [('profileid', c_uint32),
                ('perf_typeid', c_uint32),
                ('config_count', c_int),
                ('config_list', c_uint64 * 6),
               ]

class Record(Structure):
    _fields_ = [
                ('opflag', c_uint32),
                ('subid',  c_uint32),
                ('val0',   c_uint64),
                ('val1',   c_uint64),
                ('val2',   c_uint64),
                ('val3',   c_uint64),
                ('val4',   c_uint64),
                ('val5',   c_uint64),
                ('val6',   c_uint64),
             ]

def printMetadata(m):
    print('profileid: {} , perf_typeid: {} , val0:rdtscp '.format(m.profileid,m.perf_typeid), end='')
    for i in range(m.config_count):
        print(',val{}_config:{} '.format(i+1,hex(m.config_list[i])), end='')
    print('')

def printRecordHeader():
    print('opflag,subid,val0,val1,val2,val3,val4,val5,val6,nested_measure_cnt,nested_stamp_cnt,nest_lvl')

def prettyPrintRecord(aRecord):
    print('opflag:{}, subid:{}, val0:{}, val1:{},  val2:{}, val3:{}, val4:{}, val5:{}, val6:{}'.format(aRecord.opflag,aRecord.subid,aRecord.val1,aRecord.val2,aRecord.val3,aRecord.val4,aRecord.val5,aRecord.val6))

def printRecord(aRecord):
    print('{},{},{},{},{},{},{},{},{}'.format(aRecord.opflag,aRecord.subid,aRecord.val0,aRecord.val1,aRecord.val2,aRecord.val3,aRecord.val4,aRecord.val5,aRecord.val6))

def printStatsForArray(aName, anArray):
    idx=0
    max=0
    max_idx=0
    for x in anArray:
        if (idx == 0):
            max=x
            max_idx=idx
        else:
            if (x > max):
                max=x
                max_idx=idx
        idx = idx + 1
    print('{}: Max is {}, index {}'.format(aName,max,max_idx)) 

    print(aName + ": average: ",end="")
    print(statistics.mean(anArray))

    print(aName + ": mode: ",end="")
    print(statistics.mode(anArray))

    print('/tmp/'+aName + ": Population standard deviation: ",end="")
    print(statistics.pstdev(anArray))

def unpackfile(afilename):
    print ('Unpacking %s' %afilename)
    with open(afilename,'rb') as file:
        my_idx=0
        total_array=[]
        cpl0_array=[]
        cpl3_array=[]
        x = Record()
        m = Metadata()
        file.readinto(m)
        printMetadata(m)
        printRecordHeader()
        while file.readinto(x):
            val0_array.append(x.val0)
            val1_array.append(x.val1)
            val2_array.append(x.val2)
            val3_array.append(x.val3)
            val4_array.append(x.val4)
            val5_array.append(x.val5)
            val6_array.append(x.val6)
            printRecord(x)
            my_idx= my_idx + 1

#     printStatsForArray(afilename + " val1", val1_array)
#     printStatsForArray(afilename + " val2", val2_array)
#     printStatsForArray(afilename + " val3", val3_array)
#     printStatsForArray(afilename + " val4", val4_array)
#     printStatsForArray(afilename + " val5", val5_array)

# main
val0_array=[]
val1_array=[]
val2_array=[]
val3_array=[]
val4_array=[]
val5_array=[]
val6_array=[]

filename = sys.argv[-1]

if os.path.isdir(filename):
    flist=[ os.path.basename(i) for i in os.listdir(filename)]
    for afile in sorted(flist):
        unpackfile(filename+'/'+afile)
else:
    unpackfile(filename)

# printStatsForArray('execInstTotal', all_totals_array)
# printStatsForArray('cpl0', all_cpl0_array)
# printStatsForArray('cpl3', all_cpl0_array)
