#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include <map>
#include <set>

#include "disasm_container.h"

int regsize(string regname)
{
    // mm(x) series, 128 bits, i.e., 16 Bytes
    if(regname[0]=='m' && regname[1] == 'm')
        return 16;
    // xmm(x) series, 128 bits, i.e., 16 Bytes
    if(regname[0]=='x' && regname[1]=='m' && regname[2] == 'm')
        return 16;
    // st(x) fpu series, 64 bits, i.e., 8 Bytes
    if(regname[0]=='s' && regname[1] == 'm')
        return 8;

    // default, eax,ebx,ecx,edx,ss,ds,ip,bp,sp,si,di,eflags, ...
    return 4;
}

namespace mswindows{
#include <Windows.h>
#include <WinVer.h>

    bool isms(const char* imagename)
    {
        DWORD  vis = GetFileVersionInfoSize(imagename, NULL);
        //printf("\nsize of vi is %d for %s.", vis, imagename);
        if (vis == 0)
            return false;

        static LPVOID pvi = new char [vis];
        static DWORD  currentsz = vis;
        if(currentsz < vis){
            pvi = new char [vis];
            currentsz = vis;
        }

        GetFileVersionInfo(imagename, NULL, vis, pvi);
        //printf("\nfvi is located at 0x%X.", pvi);
        // Read the list of languages and code pages.
        struct LANGANDCODEPAGE {
            WORD wLanguage;
            WORD wCodePage;
        } *lpTranslate; 
        UINT cbTranslate = 0;
        VerQueryValue(pvi, TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&lpTranslate, &cbTranslate);
        //if(cbTranslate/sizeof(struct LANGANDCODEPAGE) > 1)
        //    printf("\nlang entry %d found", cbTranslate/sizeof(struct LANGANDCODEPAGE));
        char SubBlock[512];
        // Read the file description for each language and code page.
        for(unsigned i=0; i < (cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
        {
            sprintf(SubBlock,
                TEXT("\\StringFileInfo\\%04x%04x\\CompanyName"),
                lpTranslate[i].wLanguage,
                lpTranslate[i].wCodePage);
            LPVOID lpBuffer;
            UINT dwBytes;
            // Retrieve file description for language and code page "i". 
            //printf("\nchecking %s", SubBlock);
            if(VerQueryValue(pvi, SubBlock, &lpBuffer, &dwBytes))
            {
                if(strcmp((char*)lpBuffer, "Microsoft Corporation") == 0){
                    //printf("\n is from MS.");
                    return true;
                }
            }; 
        }

        return false;
    }

}

#define NUM_BUF_PAGES 8196

UINT32      count_trace = 0;

// map address and length into unique id
typedef  map<pair<ADDRINT, UINT32>, int > UniqueBBLSet;
UniqueBBLSet uniquebblset;
typedef UniqueBBLSet::iterator UniqueBBLSetIter;

struct FussionBBL{
    UINT32  id;
    ADDRINT addr; // address
    UINT32  len; // bytes insides this bbl, for its code
    UINT32  num_instructions;
    UINT64  references;  // time of execution, reference

    UINT32  readbytes;   // each time refered, bytes read
    UINT32  writebytes;  //  and bytes write

    UINT32  reginbytes;
    UINT32  regoutbytes;

    UINT64  weight; // num_instruction * references

    UINT64  memsaved; // memory access saved, in bytes

    string  disasm;
};

bool weight_bigger(const struct FussionBBL& l, const struct FussionBBL& r)
{
    return l.weight > r.weight;
};

vector<struct FussionBBL> fbbs;

typedef struct __memwallsaver{
    UINT32  bblid;
    ADDRINT addr;
    UINT32  len;
    UINT32  optype; // 0,frame break; 1,read; 2,write
} MemWallSaver;

vector<MemWallSaver> memwallpack;

BUFFER_ID   referencebuf;
BUFFER_ID   memwallbuf;
PIN_LOCK    thelock;

KNOB<string>
    KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", 
    "o", "lastprog.log", "Full log output file");

KNOB<string>
    KnobDasmFile(KNOB_MODE_WRITEONCE, "pintool", 
    "d", "lastprog.asm", "Disassembly log output file");

KNOB<string>
    KnobMemAnalyze(KNOB_MODE_WRITEONCE, "pintool", 
    "m", "0", "Analyse Memory dependecies");

FILE* loghandle  = NULL;
FILE* disasemble = NULL;
bool  analyzemem = false;

FILE* itob = NULL;

string targetprogram;

int logmsg(const char* fmt, ...)
{
    va_list vars;
    va_start (vars, fmt);
    int bytes = vfprintf(loghandle, fmt, vars);
    va_end(vars);
    return bytes;
}

map<IMG, bool> image_map;

VOID Image(IMG img, VOID *v)
{
    // logmsg("Loading \"%s\"\n", IMG_Name(img).c_str());
    if(IMG_IsMainExecutable(img)){
        printf("EXE: 0x%08X -> %s.\n", IMG_StartAddress(img), IMG_Name(img).c_str());
    }else{
        if(IMG_Valid(img)){
            printf("DLL: 0x%08X -> %s\n", IMG_StartAddress(img), IMG_Name(img).c_str());
            bool isms = mswindows::isms(IMG_Name(img).c_str());
            image_map.insert(make_pair(img, isms));
        }else{
            printf("Invalid image loaded.\n");
        }
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if(!IMG_Valid(img))
        return;
    if(image_map[img])
        return;

    GetLock(&thelock, 2);
    for (BBL bbl=TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)){
        count_trace++;

        unsigned int bblid;
        UniqueBBLSetIter i = uniquebblset.find(make_pair(BBL_Address(bbl), BBL_Size(bbl)));
        if(i == uniquebblset.end()){
            struct FussionBBL abbl = {0};
            abbl.id   = uniquebblset.size() + 1;
            bblid     = abbl.id;
            abbl.addr = BBL_Address(bbl);
            abbl.len  = BBL_Size(bbl);
            abbl.num_instructions =BBL_NumIns(bbl);
            // check the read and write of bytes from/to memory
            int b_read = 0, b_write = 0;
            for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)){
                //
                if(INS_IsMemoryRead(ins)){
                    b_read += INS_MemoryReadSize(ins);
                    if(analyzemem){
                        INS_InsertFillBuffer(ins, IPOINT_BEFORE, memwallbuf,
                            IARG_MEMORYREAD_EA,   offsetof(MemWallSaver, addr),
                            IARG_UINT32,       1, offsetof(MemWallSaver, optype),
                            IARG_UINT32,   bblid, offsetof(MemWallSaver, bblid),
                            IARG_UINT32, INS_MemoryReadSize(ins), offsetof(MemWallSaver, len),
                            IARG_END);
                    }
                }
                if(INS_HasMemoryRead2(ins)){
                    b_read += INS_MemoryReadSize(ins);
                    if(analyzemem){
                        INS_InsertFillBuffer(ins, IPOINT_BEFORE, memwallbuf,
                            IARG_MEMORYREAD2_EA, offsetof(MemWallSaver, addr),
                            IARG_UINT32,      1, offsetof(MemWallSaver, optype),
                            IARG_UINT32,  bblid, offsetof(MemWallSaver, bblid),
                            IARG_UINT32, INS_MemoryReadSize(ins), offsetof(MemWallSaver, len),
                            IARG_END);
                    }
                }
                if(INS_IsMemoryWrite(ins)){
                    b_write += INS_MemoryWriteSize(ins);
                    if(analyzemem){
                        INS_InsertFillBuffer(ins, IPOINT_BEFORE, memwallbuf,
                            IARG_MEMORYWRITE_EA, offsetof(MemWallSaver, addr),
                            IARG_UINT32,      2, offsetof(MemWallSaver, optype),
                            IARG_UINT32,  bblid, offsetof(MemWallSaver, bblid),
                            IARG_UINT32, INS_MemoryReadSize(ins), offsetof(MemWallSaver, len),
                            IARG_END);
                    }
                }
            }
            abbl.readbytes  = b_read;
            abbl.writebytes = b_write;
            abbl.memsaved   = 0;

            string traceString = ";@"+decstr(abbl.id)+" [" + IMG_Name(img) + "] [" + RTN_Name(TRACE_Rtn(trace)) + "]\n";
            int i_read, i_write;
            std::map<string,int> inputregs;
            std::map<string,int> outputregs;
            int iib = 0;
            for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)){
                traceString += hexstr(INS_Address(ins)) + " ;";
                traceString += INS_Disassemble(ins);

                traceString += "; read [";
                for(UINT32 idx=0; idx <INS_MaxNumRRegs(ins); idx++)
                {
                    string theReg = REG_StringShort(REG_FullRegName(INS_RegR(ins, idx)));
                    traceString += theReg + " ";
                    std::map<string,int>::iterator regitr = outputregs.find(theReg);
                    if(regitr == outputregs.end()){
                        // if output regs does not cover input reg, register as a input
                        inputregs[theReg] = iib;
                    }else{
                        // or, there is a internal dependant relation
                        // nothing to do presently
                    }
                }
                traceString += "], write [ ";
                for(UINT32 idx=0; idx<INS_MaxNumWRegs(ins); idx++)
                {
                    string theReg = REG_StringShort(REG_FullRegName(INS_RegW(ins, idx)));
                    traceString += theReg + " ";
                    // this will aotumatically update the updater of output register
                    // or insert an output entry, that holding the updater information
                    outputregs[theReg] = iib;
                }
                i_read  = INS_IsMemoryRead(ins)   ? INS_MemoryReadSize(ins)  : 0;
                i_read += INS_HasMemoryRead2(ins) ? INS_MemoryReadSize(ins)  : 0;
                i_write = INS_IsMemoryWrite(ins)  ? INS_MemoryWriteSize(ins) : 0;
                traceString +="], MR " + decstr(i_read) +",MW "+ decstr(i_write) + "\n";
                iib ++;
            }
            // log the input and output registers for this block
            traceString += "*Input-dependants: ";
            int inregsize = 0;
            for(std::map<string,int>::iterator regitr = inputregs.begin();
                regitr != inputregs.end(); regitr++)
            {
                traceString += regitr->first + "(" + decstr(regitr->second) + ") ";
                inregsize += regsize(regitr->first);
            }
            traceString += "\n*Live-outputs: ";
            int outregsize = 0;
            for(std::map<string,int>::iterator regitr = outputregs.begin();
                regitr != outputregs.end(); regitr++)
            {
                traceString += regitr->first + "(" + decstr(regitr->second) + ") ";
                outregsize += regsize(regitr->first);
            }
            abbl.reginbytes = inregsize;
            abbl.regoutbytes = outregsize;

            traceString += "\n";
            string itobstring = decstr(abbl.num_instructions);
            itobstring += " "+decstr(abbl.readbytes);
            itobstring += " "+decstr(abbl.writebytes);
            itobstring += " "+decstr(inregsize);
            itobstring += " "+decstr(outregsize);
            itobstring += "\n";
            traceString += itobstring;
            // we got to find that bitch
            if(abbl.readbytes > 300 || abbl.writebytes > 300){
                // found it
                printf("%s\n", traceString);
            }
            // 构造指令数到数据流量的影射关系，内存（寄存器）。这是协处理器的带宽瓶颈。
            fprintf(disasemble, "%s\n", traceString.c_str());
            fflush(disasemble);
            fprintf(itob, "%s", itobstring.c_str());
            fflush(itob);
            abbl.disasm = traceString;

            fbbs.push_back(abbl);
            uniquebblset[make_pair(abbl.addr, abbl.len)] = bblid;
        }else{
            bblid = i->second;
        }

        INS_InsertFillBuffer(BBL_InsTail(bbl), IPOINT_BEFORE, referencebuf,
            IARG_UINT32, bblid, 0, IARG_END);
        if(analyzemem){
            INS_InsertFillBuffer(BBL_InsTail(bbl), IPOINT_BEFORE, memwallbuf,
                IARG_UINT32,      0, offsetof(MemWallSaver, optype),
                IARG_UINT32,  bblid, offsetof(MemWallSaver, bblid),
                IARG_END);
        }
    }
    ReleaseLock(&thelock);
}

void backupcache()
{
    FILE* inscache = fopen("tracer.cache", "wb");
    for(size_t i = 0; i < fbbs.size(); i ++)
        fwrite(&(fbbs[i]), sizeof(struct FussionBBL), 1, inscache);
    fclose(inscache);
}

set<ADDRINT> memspots;

void ProcessPackage()
{
    // process a memory saver event package.
    UINT32     saved = 0;
    memspots.clear();

    for(size_t i = 0; i < memwallpack.size(); i++ )
    {
        if(memwallpack[i].optype == 1) // read
        {
            if(memspots.find(memwallpack[i].addr) != memspots.end())
                saved += memwallpack[i].len;
        }
        if(memwallpack[i].optype == 2) // write
        {
            memspots.insert(memwallpack[i].addr);
        }
    }

    fbbs[memwallpack[0].bblid].memsaved += saved;
    // and clean the buffer
    memwallpack.clear();
}

/*
this event handler could be converted into background, so as to save us some time, by the 
virtune of multicore of modern processors.
*/
VOID * BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf,
    UINT64 numElements, VOID *v)
{
    //logmsg("buf fuul %llu elements ready.\n", numElements);
    GetLock(&thelock, 3);
    if(id == referencebuf){
        UINT32* bblid = (UINT32*)buf;
        for(size_t n =0; n < numElements; n++){
            //if(bblid[n] >= fbbs.size()){
            //    logmsg("error id %u indexing into %u items.\n", bblid[n], fbbs);
            //}else
            fbbs[bblid[n]].references ++; // 这里也需要小心数据溢出
        }
    }else if(id == memwallbuf)
    {
        MemWallSaver* saversamples = (MemWallSaver*) buf;
        // memory wall releave record buffer full triggered.
        for(size_t m = 0; m < numElements; m ++)
        {
            if(saversamples[m].optype == 0)
                ProcessPackage();
            else
                memwallpack.push_back(saversamples[m]);
        }
    }
    ReleaseLock(&thelock);
    //logmsg("buf fuul %llu elements proccesed OK.\n", numElements);
    return buf;
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    logmsg("thread begin %d\n",threadid);
}
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    logmsg("thread end %d code %d\n",threadid, code);
}

double getGini(const vector<struct FussionBBL>& shadowfbbs)
{
    // GINI coefficient calculating
    vector<double> weights;
    vector<double> accumulated;

    size_t n_bbls = shadowfbbs.size();

    weights.resize(n_bbls);
    accumulated.resize(n_bbls);

    // 首先构造权重数组，并从小到大排序
    for(size_t i = 0; i < n_bbls; i ++)
        weights[i] = shadowfbbs[i].weight;
    sort(weights.begin(), weights.end()); // smaller first, sorted.

    // 计算到每一个样本处，累加的权重。最后一个也就是全部的权重总和
    double accu_weight  = 0;
    for(size_t i = 0; i < n_bbls; i ++){
        accu_weight    += weights[i];
        accumulated[i]  = accu_weight;
    }
    // 计算每一个样本点处，累加的权重占到总权重的比例，以及这些比例的和
    double weighted2    = 0;
    for(size_t i = 0; i < n_bbls; i ++){
        accumulated[i] /= accu_weight;
        weighted2 += accumulated[i];
    }

    // 得到基尼系数，权重分布的不均衡程度。0-1，完全均匀分布到完全集中
    double gini = 1.0 - 2.0 * weighted2 / n_bbls;

    // fprintf(stderr, "accu weight %f, intergrated weight %f\n", accu_weight, weighted2);
    // fflush(stderr);

    return gini;
}

// 输入的vector应该已经是按照权重从大到小排列好的一个向量，以及需要融合的BBL代码块数量
// 主返回值为能够减少的指令执行条数，次返回值为跳过了多少个单指令BBL代码块。
UINT64 getReducedHits(const vector<struct FussionBBL>& shadowfbbs, int num_fussion,
    double* ins_blk=NULL, double* ins_blk_weigh=NULL, int* skipped = NULL, UINT64* memsaved = NULL)
{
    UINT64 reducedhits = 0;

    int fussed     = 0;
    int itomicblks = 0;
    int ins_local  = 0;
    UINT64 refs_local = 0;
    UINT64 hits_local = 0;
    UINT64 mems = 0;
    for(size_t i = 0; i < shadowfbbs.size(); i ++)
    {
        if(shadowfbbs[i].num_instructions == 1){
            itomicblks ++;
            continue;
        }
        // 可以减少的指令数量=该指令BBL块变成只含有一条指令。
        reducedhits += shadowfbbs[i].weight - shadowfbbs[i].references;
        fussed ++;
        ins_local += shadowfbbs[i].num_instructions;
        refs_local += shadowfbbs[i].references;
        hits_local += shadowfbbs[i].weight;

        mems += shadowfbbs[i].memsaved;

        //fprintf(stderr, "%s\n", shadowfbbs[i].disasm.c_str());

        if(fussed >= num_fussion)
            break;
    }

    // 对于原来就只有一条指令的基本块，指令融合将失去作用
    if(skipped)
        *skipped = itomicblks;
    if(ins_blk)
        *ins_blk = 1.0 * ins_local / num_fussion;
    if(ins_blk_weigh)
        *ins_blk_weigh = 1.0 * hits_local / refs_local;
    if(memsaved)
        *memsaved = mems;

    return reducedhits;
}

static double alpha = 5.4; // 5.4 slices per instruction is estimated.
static double beta  = 3;   // 3 slices per BBL is needed for the interfacing.
UINT64 boundedselect(const vector<struct FussionBBL>& shadowfbbs, int slicsmark,
    int* ins_num, int* slicesused, double* ins_bf, double* ins_bfw)
{
    UINT64 hits = 0;
    int slices = 0;
    *ins_num = 0;
    // *slicesused = 0;
    *ins_bf = 0.0; *ins_bfw = 0.0;
    UINT64 refs_local = 0;
    for(unsigned int i = 0; i < shadowfbbs.size(); i ++)
    {
        if(shadowfbbs[i].num_instructions == 1)
            continue;
        double tempslice = slices + shadowfbbs[i].num_instructions * alpha + beta;
        if(tempslice > 1.0*slicsmark)
            break;
        hits += shadowfbbs[i].weight - shadowfbbs[i].references;
        slices = 1 + (int)floor(tempslice);
        (*ins_num) ++;
        *ins_bf += shadowfbbs[i].num_instructions;
        *ins_bfw += shadowfbbs[i].weight;

        refs_local += shadowfbbs[i].references;
    }

    *ins_bf /= *ins_num;
    *ins_bfw /= refs_local;
    *slicesused = slices;

    return hits;
}

void onlineanalyze()
{
    UINT64 total_bbl_hits = 0;
    UINT64 total_ins = 0;
    UINT64 total_ins_hits = 0;
    size_t total_bbls = fbbs.size();
    UINT64 total_memaccess = 0;
    for(size_t i = 0; i < total_bbls; i ++){
        total_bbl_hits += fbbs[i].references;
        total_ins += fbbs[i].num_instructions;
        // 检查数据溢出
        fbbs[i].weight = fbbs[i].references * fbbs[i].num_instructions;
        total_ins_hits+= fbbs[i].weight;
        // if(references[i] < 0)
        //   fprintf(stderr, "%ld reference found, %ld instructions inside that block.\n", references[i], instructions[i]);
        total_memaccess += (fbbs[i].readbytes + fbbs[i].writebytes)*fbbs[i].references;
    }

    // statistic
    double ins_per_block = 1.0 * total_ins / total_bbls;
    double ins_per_block_weighted = 1.0 * total_ins_hits / total_bbl_hits;
    // logmsg("Total basic block hits %lld\n", th);
    logmsg("Average instruction per block %f, weighted %f\n", ins_per_block, ins_per_block_weighted);
    // logmsg("Total instruction hit %llu.\n", totalinshit);
    // logmsg("Average instruction hits per block %f, over %llu block hits.\n", 1.0 * totalinshit / th, th);

    // 统计分析指令融合的效果之前，首先将权重（耗费在此基本块上的指令执行条数）从大到小排序
    sort(fbbs.begin(), fbbs.end(), weight_bigger);

    static int reducingparmeter[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 0};
    logmsg("融合指令:  执行时间收益： 执行速度增加， 融合部分块平均指令， 加权的块平均指令数， 内存屏障收益\n");
    for(int i = 0; reducingparmeter[i]; i++)
    {
        double ins_bf, ins_bfw;
        UINT64 memaccesssaved = 0;
        UINT64 reducedhits = getReducedHits(fbbs, reducingparmeter[i], &ins_bf, &ins_bfw, NULL, &memaccesssaved);
        double time_tobe = 100.0 * (total_ins_hits - reducedhits) / total_ins_hits;
        double speedup = 10000.0 / time_tobe;
        double memwallgain = 100.0 * memaccesssaved / total_memaccess;
        logmsg("%4d: %f%%, %f%%, %f, %f, %f%%.\n", 
            reducingparmeter[i], 100.0 - time_tobe, speedup - 100.0, ins_bf, ins_bfw, memwallgain);
    }
    static int slicesmark[] = {768,960, 2400, 6144,17280, 46560, 0}; // sparton 3, 3e 6; vertex 4,5,6 level
    logmsg("硬件资源：融合指令数，执行时间收益，实行速度增加比例，融合部分块平均指令， 加权的块平均指令数, 资源利用率\n");
    for(int i =0; slicesmark[i]; i++)
    {
        double ins_bf, ins_bfw;
        int    ins_num, slicesused;
        UINT64 hitssaved = boundedselect(fbbs, slicesmark[i], &ins_num, &slicesused, &ins_bf, &ins_bfw);
        double timenew = 100.0 * (total_ins_hits - hitssaved) / total_ins_hits;
        double speednew= 10000.0 / timenew;
        logmsg("%5d: %4d, %f%%, %f%%, %f, %f, %f%%\n", 
            slicesmark[i], ins_num, 
            100.0 - timenew, speednew - 100.0, ins_bf, ins_bfw, 100.0 * slicesused / slicesmark[i]);
    }
    double gini = getGini(fbbs);
    logmsg("Gini coefficient %f.\n", gini);

    logmsg("Top 10 BBL(s)\n");
    for(int i =0; i < 10; i ++)
        logmsg("%lld, %s\n", fbbs[i].references, fbbs[i].disasm.c_str());

}

void Fini(INT32 code, VOID *v)
{
    logmsg("Basic Block acounted %d, %lu unique.\n", count_trace, fbbs.size());

    // backupcache();
    onlineanalyze();
    fclose(loghandle);
    fclose(disasemble);
    fclose(itob);
}

int  main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
        return -1;

    loghandle  = fopen(KnobOutputFile.Value().c_str(), "a");
    disasemble = fopen(KnobDasmFile.Value().c_str(), "w");
    itob = fopen("itob.log", "a");
    analyzemem = (0 != atoi(KnobMemAnalyze.Value().c_str()));

    int i = 0;
    for(; i < argc; i ++)
        if(argv[i][0] == '-' && argv[i][1] == '-')
            break;
    for(i++; i < argc; i ++)
        targetprogram = targetprogram + argv[i] + " ";

    __time64_t ltime;
    _time64( &ltime );
    logmsg("\n\nThe time is %s", _ctime64( &ltime ) ); // C4996
    logmsg("CMD: %s\n", targetprogram.c_str());

    IMG_AddInstrumentFunction(Image, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    referencebuf = PIN_DefineTraceBuffer(
        sizeof(UINT32), NUM_BUF_PAGES, BufferFull, 0);
    memwallbuf =  PIN_DefineTraceBuffer(
        sizeof(MemWallSaver), NUM_BUF_PAGES, BufferFull, 0);

    InitLock(&thelock);
    PIN_StartProgram();
    return 0;
}
