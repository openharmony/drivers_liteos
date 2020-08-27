/*
 * Copyright (c) 2013-2019, Huawei Technologies Co., Ltd. All rights reserved.
 * Copyright (c) 2020, Huawei Device Co., Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tzdriver_compat.h"
#include "mbedtls/aes.h"

LosTaskCB *KthreadRun(int (*threadfn)(UINTPTR data, int dataLen), void *data, int dataLen, char *name)
{
    LosTaskCB *ktask = NULL;
    UINT32 taskId = 0;
    UINT32 ret;
    TSK_INIT_PARAM_S taskInitParam;

    if (memset_s(&taskInitParam, sizeof(TSK_INIT_PARAM_S), 0, sizeof(TSK_INIT_PARAM_S)) != EOK) {
        return NULL;
    }

    taskInitParam.pfnTaskEntry = (TSK_ENTRY_FUNC)threadfn;
    taskInitParam.uwStackSize  = LOSCFG_BASE_CORE_TSK_DEFAULT_STACK_SIZE;
    taskInitParam.pcName       = name;
    taskInitParam.usTaskPrio   = 1;
    taskInitParam.auwArgs[0]   = (UINTPTR)data;
    taskInitParam.auwArgs[1]   = dataLen;
    taskInitParam.uwResved     = LOS_TASK_STATUS_DETACHED;

    ret = LOS_TaskCreate(&taskId, &taskInitParam);
    if (ret != LOS_OK) {
        return NULL;
    }

    ktask = (LosTaskCB *)OS_TCB_FROM_TID(taskId);
    (VOID)LOS_TaskYield();
    return ktask;
}

int KthreadStop(LosTaskCB *k)
{
    return LOS_TaskDelete(k->taskID);
}

int KthreadShouldStop(void)
{
    return (OsCurrTaskGet()->signal == SIGNAL_KILL);
}

#define MAX_HEX_BITS_NUM 0x10000000
#define ONE_HEX_NUM_OFFSET 4 // 0-9 a-f number contains 4 bit
#define HEX_TEN 0xa
static int AsciiToNumber(char c)
{
    return (c - '0');
}

static int HexAsciiToNumber(char c)
{
    return (c - 'A' + HEX_TEN);
}


static int Toupper(int c)
{
    return  (((c) >= 'a' && (c) <= 'z') ? ((c) - 'a' + 'A') : (c));
}

static int IsDigit(char c)
{
    return (c >= '0' && c <= '9');
}

static int Atoulx(char *str, unsigned int *pulValue)
{
    unsigned int ulResult = 0;
    char ch;

    while (*str) {
        ch = Toupper((int)*str);
        if (IsDigit(ch) || ((ch >= 'A') && (ch <= 'F'))) {
            if (ulResult < MAX_HEX_BITS_NUM) {
                ulResult = (ulResult << ONE_HEX_NUM_OFFSET) + ((ch <= '9') ?
                    (AsciiToNumber(ch)) : (HexAsciiToNumber(ch)));
            } else {
                *pulValue = ulResult;
                return -1;
            }
        } else {
            *pulValue = ulResult;
            return -1;
        }
        str++;
    }

    *pulValue = ulResult;
    return 0;
}

#define MAX_DEC_BITS_NUM 429496729 // 0XFFFFFFFF / 10S
#define DEC_UNIT 10

static int Atoul(char *str, unsigned int *pulValue)
{
    unsigned int ulResult = 0;

    while (*str) {
        if (IsDigit(*str)) {
            if ((ulResult < MAX_DEC_BITS_NUM) || ((ulResult == MAX_DEC_BITS_NUM) && (*str < '6'))) {
                ulResult = ulResult * DEC_UNIT + (*str) - '0';
            } else {
                *pulValue = ulResult;
                return -1;
            }
        } else {
            *pulValue = ulResult;
            return -1;
        }
        str++;
    }
    *pulValue = ulResult;
    return 0;
}

#define OCT 8
#define DEC 10
#define HEX 16
#define HEX_SPILT_LEN 2 // sizeof '0x'

int KstrToU32(char *str, int base, unsigned int *pulValue)
{
    int baseRecong;
    if (base == 0) {
        if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
            baseRecong = HEX;
        } else if (*str == '0') {
            baseRecong = OCT;
        } else {
            baseRecong = DEC;
        }
    } else {
        baseRecong = DEC;
    }

    switch (baseRecong) {
        case OCT:
            // unsupport
            return -1;
        case DEC:
            return Atoul(str, pulValue);
        case HEX:
            return Atoulx(str + HEX_SPILT_LEN, pulValue);
        default:
            break;
    }
    return -1;
}

ssize_t SimpleReadFromBuffer(void __user *to, size_t count,
                const void *from, size_t available)
{
    size_t ret;

    ret = copy_to_user(to, from, count);
    if (ret == count) {
        return -EFAULT;
    }
    count -= ret;
    return count;
}

LosVmPage *MailboxPoolAllocPages(unsigned int order)
{
    void *ptr = LOS_PhysPagesAllocContiguous(1UL << order);
    if (ptr == NULL) {
        PRINTK("mailbox pool contiguous ptr null size %x\n", 1 << order);
        return NULL;
    }
    for (int i = 0; i < (1UL << order); i++) {
        // mempool is used to mmap, add ref to prevent pmm free page to free list.
        LosVmPage *page = OsVmVaddrToPage((void *)((intptr_t)ptr + PAGE_SIZE * i));
        if (page != NULL) {
            LOS_AtomicInc(&page->refCounts);
        }
    }

    return OsVmVaddrToPage(ptr);
}

void MailboxPoolFreePages(LosVmPage *pageArray, size_t order)
{
    for (int i = 0; i < (1UL << order); i++) {
        LOS_AtomicDec(&(pageArray[i].refCounts));
        LOS_PhysPageFree(&pageArray[i]);
    }
    LOS_PhysPagesFreeContiguous(pageArray, (1UL << order));
}

INT32 DoVmallocRemap(LosVmMapRegion *vma, void *kvaddr)
{
    int i;
    int ret = 0;
    paddr_t pa;
    UINT32 uflags = VM_MAP_REGION_FLAG_PERM_READ | VM_MAP_REGION_FLAG_PERM_WRITE | VM_MAP_REGION_FLAG_PERM_USER;
    LosVmPage *vmPage = NULL;
    LosVmSpace *vSpace = LOS_SpaceGet(vma->range.base);
    vaddr_t kva = (vaddr_t)(uintptr_t)kvaddr;
    vaddr_t uva = vma->range.base;
    unsigned int page;

    (VOID)LOS_MuxAcquire(&vSpace->regionMux);

    for (i = 0; i < (vma->range.size >> PAGE_SHIFT); i++) {
        page = (unsigned int)i;
        pa = LOS_PaddrQuery((void *)(uintptr_t)(kva + (page << PAGE_SHIFT)));
        if (pa == 0) {
            PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
            ret = -EINVAL;
            break;
        }
        vmPage = LOS_VmPageGet(pa);
        if (vmPage == NULL) {
            PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
            ret = -EINVAL;
            break;
        }
        status_t err = LOS_ArchMmuMap(&vSpace->archMmu, uva + (page << PAGE_SHIFT), pa, 1, uflags);
        if (err < 0) {
            ret = err;
            PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
            break;
        }
        LOS_AtomicInc(&vmPage->refCounts);
    }
    /* if any failure happened, rollback */
    if (i < (vma->range.size >> PAGE_SHIFT)) {
        for (i = i - 1; i >= 0; i--) {
            page = (unsigned int)i;
            pa = LOS_PaddrQuery((void *)(uintptr_t)(kva + (page << PAGE_SHIFT)));
            vmPage = LOS_VmPageGet(pa);
            (VOID)LOS_ArchMmuUnmap(&vSpace->archMmu, uva + (page << PAGE_SHIFT), 1);
            (VOID)LOS_PhysPageFree(vmPage);
        }
    }

    (VOID)LOS_MuxRelease(&vSpace->regionMux);
    return ret;
}

int RemapVmallocRange(LosVmMapRegion *vma, void *addr,
    unsigned long pgoff)
{
    if (pgoff != 0) {
        return -1;
    }
    return DoVmallocRemap(vma, addr);
}

int CreateTcClientDevice(const char *devName, const struct file_operations_vfs *op)
{
    int ret = register_driver(devName, op, TEE_DEV_PRI, NULL);
    if (unlikely(ret)) {
        return -1;
    }

    return EOK;
}

#define IV_LEN 16
#define KEY_BITS 256
#define MAX_AES_CRYPT_SIZE SZ_4M
int CryptoAescbcKey256(unsigned char *output, const unsigned char *input, struct AesParam *param)
{
    mbedtls_aes_context ctx;
    int ret;
    if (!output || !input) {
        return -1;
    }

    if (!param || !param->iv || !param->key ||
        param->size < 0 ||  param->size > MAX_AES_CRYPT_SIZE) {
        return -1;
    }
    int mode = param->encryptoType ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
    unsigned char ivTmp[IV_LEN] = {0};

    ret = memcpy_s(ivTmp, IV_LEN, param->iv, IV_LEN);
    if (ret != EOK) {
        return -1;
    }
    mbedtls_aes_init(&ctx);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        ret = mbedtls_aes_setkey_enc(&ctx, param->key, KEY_BITS);
    } else {
        ret = mbedtls_aes_setkey_dec(&ctx, param->key, KEY_BITS);
    }
    if (ret) {
        return -1;
    }
    return mbedtls_aes_crypt_cbc(&ctx, mode, param->size, ivTmp, input, output);
}

void SetVmmRegionCodeStart(UINTPTR codeStart, UINT32 codeSize)
{
    LosVmSpace *space = NULL;
    space = OsCurrProcessGet()->vmSpace;
    if (space->codeStart != 0) {
        return;
    }
    space->codeStart = codeStart;
    space->codeEnd = codeStart + codeSize;
}
