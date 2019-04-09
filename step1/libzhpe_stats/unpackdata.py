#!/usr/bin/python3

import os
import struct
import sys
from ctypes import *
import statistics

class ProcCtlCacheData(Structure):
    _pack_ = 1
    _fields_ = [('ctlval', c_uint16),
                ('ctlversion', c_uint16),
                ('execInstTotal', c_uint64),
                ('cpl0ExecInstTotal', c_uint64),
                ('cpl1ExecInstTotal', c_uint64),
                ('cpl2ExecInstTotal', c_uint64),
                ('cpl3ExecInstTotal', c_uint64),
    		('cacheval', c_uint16),
                ('cacheversion', c_uint16),
                ('coherencyCastoutDataL1', c_uint64),
                ('coherencyCastoutInstL1', c_uint64),
                ('capacityCastoutDataL1', c_uint64),
                ('capacityCastoutInstL1', c_uint64),
                ('lineMissDataL1', c_uint64),
                ('lineHitDataL1', c_uint64),
                ('lineMissInstL1', c_uint64),
                ('lineHitInstL1', c_uint64),
                ('uncachedReadInstL1', c_uint64),
                ('uncachedReadDataL1', c_uint64),
                ('uncachedWriteDataL1', c_uint64),
                ('lineCastoutDirtyDataL1', c_uint64),
                ('coherencyCastoutDataL2', c_uint64),
                ('capacityCastoutDataL2', c_uint64),
                ('lineMissDataL2', c_uint64),
                ('lineHitDataL2', c_uint64),
                ('lineCastoutDirtyDataL2', c_uint64),
                ('lineMissWriteThroughL2', c_uint64),
                ('zhpeStatsStarts', c_uint32),
                ('zhpeStatsPauses', c_uint32),
                ('zhpeSubId', c_uint32),
                ('zhpeNesting', c_uint32)]

def printProcCtlCacheDataHeader():
    print('execInstTotal,cpl0ExecInstTotal,cpl1ExecInstTotal,cpl2ExecInstTotal,cpl3ExecInstTotal,coherencyCastoutDataL1,coherencyCastoutInstL1,capacityCastoutDataL1,capacityCastoutInstL1,lineMissDataL1,lineHitDataL1,lineMissInstL1,lineHitInstL1,uncachedReadInstL1,uncachedReadDataL1,uncachedWriteDataL1,lineCastoutDirtyDataL1,coherencyCastoutDataL2,capacityCastoutDataL2,lineMissDataL2,lineHitDataL2,lineCastoutDirtyDataL2,lineMissWriteThroughL2,zhpeStatsStarts,zhpeStatsPauses,zhpeSubId')

def prettyPrintProcCtlCacheData(aProcCtlCacheData, anIdx):
    print('execInstTotal:{}, cpl0ExecInstTotal:{},  cpl1ExecInstTotal:{},  cpl2ExecInstTotal:{},  cpl3ExecInstTotal:{}, coherencyCastoutDataL1:{},coherencyCastoutInstL1:{},capacityCastoutDataL1:{},capacityCastoutInstL1:{},lineMissDataL1:{},lineHitDataL1:{},lineMissInstL1:{},lineHitInstL1:{},uncachedReadInstL1:{},uncachedReadDataL1:{},uncachedWriteDataL1:{},lineCastoutDirtyDataL1:{},coherencyCastoutDataL2:{},capacityCastoutDataL2:{},lineMissDataL2:{},lineHitDataL2:{},lineCastoutDirtyDataL2:{},lineMissWriteThroughL2:{},zhpeStatsStarts:{},zhpeStatsPauses:{},zhpeSubId:{},zhpeNesting:{}'.format(aProcCtlCacheData.execInstTotal,aProcCtlCacheData.cpl0ExecInstTotal, aProcCtlCacheData.cpl1ExecInstTotal, aProcCtlCacheData.cpl2ExecInstTotal, aProcCtlCacheData.cpl3ExecInstTotal,aProcCtlCacheData.coherencyCastoutDataL1,aProcCtlCacheData.coherencyCastoutInstL1,aProcCtlCacheData.capacityCastoutDataL1,aProcCtlCacheData.capacityCastoutInstL1,aProcCtlCacheData.lineMissDataL1,aProcCtlCacheData.lineHitDataL1,aProcCtlCacheData.lineMissInstL1,aProcCtlCacheData.lineHitInstL1,aProcCtlCacheData.uncachedReadInstL1,aProcCtlCacheData.uncachedReadDataL1,aProcCtlCacheData.uncachedWriteDataL1,aProcCtlCacheData.lineCastoutDirtyDataL1,aProcCtlCacheData.coherencyCastoutDataL2,aProcCtlCacheData.capacityCastoutDataL2,aProcCtlCacheData.lineMissDataL2,aProcCtlCacheData.lineHitDataL2,aProcCtlCacheData.lineCastoutDirtyDataL2,aProcCtlCacheData.lineMissWriteThroughL2,aProcCtlCacheData.zhpeStatsStarts,aProcCtlCacheData.zhpeStatsPauses,aProcCtlCacheData.zhpeSubId,aProcCtlCacheData.zhpeNesting))


def printProcCtlCacheData(aProcCtlCacheData, anIdx):
    print('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(aProcCtlCacheData.execInstTotal,aProcCtlCacheData.cpl0ExecInstTotal, aProcCtlCacheData.cpl1ExecInstTotal, aProcCtlCacheData.cpl2ExecInstTotal, aProcCtlCacheData.cpl3ExecInstTotal,aProcCtlCacheData.coherencyCastoutDataL1,aProcCtlCacheData.coherencyCastoutInstL1,aProcCtlCacheData.capacityCastoutDataL1,aProcCtlCacheData.capacityCastoutInstL1,aProcCtlCacheData.lineMissDataL1,aProcCtlCacheData.lineHitDataL1,aProcCtlCacheData.lineMissInstL1,aProcCtlCacheData.lineHitInstL1,aProcCtlCacheData.uncachedReadInstL1,aProcCtlCacheData.uncachedReadDataL1,aProcCtlCacheData.uncachedWriteDataL1,aProcCtlCacheData.lineCastoutDirtyDataL1,aProcCtlCacheData.coherencyCastoutDataL2,aProcCtlCacheData.capacityCastoutDataL2,aProcCtlCacheData.lineMissDataL2,aProcCtlCacheData.lineHitDataL2,aProcCtlCacheData.lineCastoutDirtyDataL2,aProcCtlCacheData.lineMissWriteThroughL2,aProcCtlCacheData.zhpeStatsStarts,aProcCtlCacheData.zhpeStatsPauses,aProcCtlCacheData.zhpeSubId,aProcCtlCacheData.zhpeNesting))


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
        printProcCtlCacheDataHeader()
        x = ProcCtlCacheData()
        while file.readinto(x):
            all_totals_array.append(x.execInstTotal)
            all_cpl0_array.append(x.cpl0ExecInstTotal)
            all_cpl3_array.append(x.cpl3ExecInstTotal)
            total_array.append(x.execInstTotal)
            cpl0_array.append(x.cpl0ExecInstTotal)
            cpl3_array.append(x.cpl3ExecInstTotal)
            printProcCtlCacheData(x,my_idx)        
            my_idx= my_idx + 1
            if (x.execInstTotal != x.cpl0ExecInstTotal + x.cpl3ExecInstTotal):
                print('Warning: {}: {} + {} != {}'.format(afilename,x.cpl0ExecInstTotal, x.cpl3ExecInstTotal,x.cpl3ExecInstTotal))
 #    printStatsForArray(afilename + " cpl0ExecInstTotal", cpl0_array)
  #   printStatsForArray(afilename + " cpl3ExecInstTotal", cpl3_array)
   #  printStatsForArray(afilename + " execInstTotal", total_array)
          
# main
all_totals_array=[]
all_cpl0_array=[]
all_cpl3_array=[]

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
