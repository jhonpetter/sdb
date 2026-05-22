/*
* SDB - Smart Development Bridge
*
* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
*
* Contact:
* Ho Namkoong <ho.namkoong@samsung.com>
* Yoonki Park <yoonki.park@samsung.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Contributors:
* - S-Core Co., Ltd
*
*/

#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <stdio.h>

#if defined(OS_WINDOWS) // for Windows
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <winbase.h>
#endif

#include "sdb_constants.h"
#include "file_sync_client.h"
#include "file_sync_functions.h"
#include "utils.h"
#include "strutils.h"
#include "fdevent.h"
#include "log.h"
#include "sdb_messages.h"

#define SDB_PROGRESS_TIME               (1)         /* 1 second */
#define SDB_PROGRESS_TOLERANCE_TIME     (500*1000)  /* 500 millisecond */

#define SDB_PROGRESS_STAGE_STARTED      0
#define SDB_PROGRESS_STAGE_TRANSFERRING 1
#define SDB_PROGRESS_STAGE_FINISHED     2

PROGRESS_INFO g_prg_info;

void print_progress(int stage);

static __inline__ void finalize(int srcfd, int dstfd, SYNC_INFO* sync_info);

void create_copy_info(COPY_INFO** info, char* srcp, char* dstp, struct stat* src_stat) {
    *info = (COPY_INFO*)malloc(sizeof(COPY_INFO));
    (*info)->src = srcp;
    (*info)->dst = dstp;
    (*info)->_stat = *src_stat;
}

static __inline__ void finalize(int srcfd, int dstfd, SYNC_INFO* sync_info) {
    sync_info->srcF->finalize(srcfd);
    sync_info->dstF->finalize(dstfd);
}

#if defined(OS_LINUX) || defined(OS_DARWIN) // for UNIX
static void update_progress(int ignore) {
    print_progress(SDB_PROGRESS_STAGE_TRANSFERRING);
    signal(SIGALRM, update_progress);
    alarm(SDB_PROGRESS_TIME);
}

static void init_sync_progress_timer(void) {
    signal(SIGALRM, update_progress);
    alarm(SDB_PROGRESS_TIME);
}

static void deinit_sync_progress_timer(void) {
    alarm(0);
}
#else // for Windows
HANDLE hTimer = NULL;

static VOID CALLBACK update_progress(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    if (hTimer != NULL) {
        print_progress(SDB_PROGRESS_STAGE_TRANSFERRING);
    }
}

static void init_sync_progress_timer(void) {
    if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)update_progress,
                                NULL, 0, (SDB_PROGRESS_TIME*1000), 0)) {
        D("failed to CreateTimerQueueTimer()\n");
        return;
    }
}

static void deinit_sync_progress_timer(void) {
    if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
        D("failed to DeleteTimerQueueTimer()\n");
        return;
    }
    hTimer = NULL;
}
#endif

static unsigned int calc_progress_speed(int stage, unsigned progress_bytes) {
    unsigned elapsed_bytes = 0;
    static unsigned prev_progress_bytes = 0;
    long long elapsed_time = 0;
    long long current_time = 0;
    static long long last_time = 0;
    unsigned speed = 0;
    static unsigned prev_speed = 0;

    // elapsed bytes
    elapsed_bytes = progress_bytes - prev_progress_bytes;
    prev_progress_bytes = progress_bytes;

    // elapsed time
    current_time = NOW();
    if (stage == SDB_PROGRESS_STAGE_STARTED) {
        elapsed_time = 0;
        last_time = current_time;
    } else {
        elapsed_time = current_time - last_time;
    }

    // progress speed
    if (elapsed_time < (SDB_PROGRESS_TOLERANCE_TIME)) {
        if (prev_speed == 0) {
            speed = 0;
        } else {
            speed = prev_speed;
        }
    } else {
        speed = ((((long long) elapsed_bytes) * 1000000LL) / elapsed_time) / 1024LL;
        prev_speed = speed;
        last_time = current_time;
    }

    if (stage == SDB_PROGRESS_STAGE_FINISHED) {
        prev_progress_bytes = 0;
        last_time = 0;
        prev_speed = 0;
    }

    return speed;
}

static unsigned calc_progress_percent(unsigned progress_bytes) {
    unsigned percent = 0;

    if (g_prg_info.total_bytes != 0) {
        percent = 100.0 * progress_bytes / g_prg_info.total_bytes;
        percent = SDB_MAX(percent, 0);
        percent = SDB_MIN(percent, 100);
    } else {
        percent = 100;
    }

    return percent;
}

void print_progress(int stage) {
    unsigned percent = 0;
    unsigned speed = 0;
    unsigned progress_bytes = 0;
    static int is_finished = 0;

    /* initialize timer */
    if (stage == SDB_PROGRESS_STAGE_STARTED) {
        init_sync_progress_timer();
        is_finished = 0;
    }

    /* calc progress information */
    sdb_mutex_lock(&prg_info_lock, "read written_bytes. print_progress()");
    progress_bytes = g_prg_info.written_bytes;
    sdb_mutex_unlock(&prg_info_lock, "read written_bytes. print_progress()");

    speed = calc_progress_speed(stage, progress_bytes);
    percent = calc_progress_percent(progress_bytes);

    /* print progress information */
    sdb_mutex_lock(&prg_print_lock, "print progress info. print_progress()");
    if (!is_finished) {
        //TODO: consider current window size.
        fprintf(stdout,"\r%s %30s\t%3d%%\t%7d%s\t%5dKB/s", g_prg_info.tag, g_prg_info.file_name,
                percent, (progress_bytes/g_prg_info.flag_size), g_prg_info.byte_flag, speed);
        fflush(stdout);
    }
    sdb_mutex_unlock(&prg_print_lock, "print progress info. print_progress()");

    /* deinitialize timer and print '\n' */
    if (stage == SDB_PROGRESS_STAGE_FINISHED) {
        deinit_sync_progress_timer();

        sdb_mutex_lock(&prg_print_lock, "print progress info. print_progress()");
        fprintf(stdout,"\n");
        fflush(stdout);
        is_finished = 1;
        sdb_mutex_unlock(&prg_print_lock, "print progress info. print_progress()");
    }
}

static void init_progress_info(char* filename, char* tag, unsigned total_bytes) {
    g_prg_info.file_name = filename;
    g_prg_info.tag = tag;
    g_prg_info.total_bytes = total_bytes;

    /**
     * The written_bytes variable can cause a thread contention
     * between main thread and timer thread.
     * Therefore, the atomic operation should be used for that variable.
     */
    g_prg_info.written_bytes = 0;

    if (g_prg_info.total_bytes < (10*1024)) {
        g_prg_info.flag_size = 1;
        g_prg_info.byte_flag[0] = ' ';
        g_prg_info.byte_flag[1] = 'B';
        g_prg_info.byte_flag[2] = '\0';
    } else if (g_prg_info.total_bytes < (10*1024*1024)) {
        g_prg_info.flag_size = 1024;
        g_prg_info.byte_flag[0] = 'K';
        g_prg_info.byte_flag[1] = 'B';
        g_prg_info.byte_flag[2] = '\0';
    } else {
        g_prg_info.flag_size = (1024*1024);
        g_prg_info.byte_flag[0] = 'M';
        g_prg_info.byte_flag[1] = 'B';
        g_prg_info.byte_flag[2] = '\0';
    }
}

static int file_copy(int src_fd, int dst_fd, COPY_INFO* copy_info, SYNC_INFO* sync_info) {
    char* srcp = copy_info->src;
    char* dstp = copy_info->dst;
    struct stat* src_stat = &(copy_info->_stat);
    D("file is copied from 'fd:%d' '%s' to 'fd:%d' '%s'\n", src_fd, srcp, dst_fd, dstp);

    FILE_FUNC* srcF = sync_info->srcF;
    FILE_FUNC* dstF = sync_info->dstF;

    init_progress_info(get_filename(srcp), sync_info->tag, src_stat->st_size);

    /**
     * local should be opend first
     * because if remote opens successfully, and fail to open local,
     * remote channel is created and protocol confliction is made
     * it is ok to other pull or push process if remote connection is not made
     */
    if(!strcmp(sync_info->tag, "pushed")) {
        src_fd = srcF->readopen(src_fd, srcp, src_stat);
        if(src_fd < 0) {
            return -1;
        }
        dst_fd = dstF->writeopen(dst_fd, dstp, src_stat);
        if(dst_fd < 0) {
            srcF->readclose(src_fd);
            return -1;
        }
    }
    else {
        dst_fd = dstF->writeopen(dst_fd, dstp, src_stat);
        if(dst_fd < 0) {
            return -1;
        }
        src_fd = srcF->readopen(src_fd, srcp, src_stat);
        if(src_fd < 0) {
            dstF->writeclose(dst_fd, dstp, src_stat);
            return -1;
        }
    }

    FILE_BUFFER srcbuf;
    srcbuf.id = sync_data;

    print_progress(SDB_PROGRESS_STAGE_STARTED);
    while(1) {
        int ret = srcF->readfile(src_fd, srcp, src_stat, &srcbuf);
        if(ret == 0) {
            break;
        }
        else if(ret == 1) {
            if(dstF->writefile(dst_fd, dstp, &srcbuf, sync_info)) {
                goto error;
            }
            sdb_mutex_lock(&prg_info_lock, "inc written_bytes. file_copy()");
            g_prg_info.written_bytes += srcbuf.size;
            sdb_mutex_unlock(&prg_info_lock, "inc written_bytes. file_copy()");
        }
        else if(ret == 2) {
            continue;
        }
        else if(ret == 3) {
            if(dstF->writefile(dst_fd, dstp, &srcbuf, sync_info)) {
                goto error;
            }
            sdb_mutex_lock(&prg_info_lock, "inc written_bytes. file_copy()");
            g_prg_info.written_bytes += srcbuf.size;
            sdb_mutex_unlock(&prg_info_lock, "inc written_bytes. file_copy()");
            break;
        }
        else {
            goto error;
        }
    }
    print_progress(SDB_PROGRESS_STAGE_FINISHED);
    if(srcF->readclose(src_fd) < 0 || dstF->writeclose(dst_fd, dstp, src_stat) < 0) {
        return -1;
    }

    return 0;

error:
    print_progress(SDB_PROGRESS_STAGE_FINISHED);
    srcF->readclose(src_fd);
    dstF->writeclose(dst_fd, dstp, src_stat);
    return -1;
}

static void free_copyinfo(void* data) {
    COPY_INFO* info = (COPY_INFO*)data;
    if(info != NULL) {
        SAFE_FREE(info->src);
        SAFE_FREE(info->dst);
        SAFE_FREE(info);
    }
}

int do_sync_copy(char* srcp, char* dstp, SYNC_INFO* sync_info, int is_utf8) {

    D("copy %s to the %s\n", srcp, dstp);
    long long start_time = NOW();

    int src_fd = 0;
    int dst_fd = 0;

    FILE_FUNC* srcF = sync_info->srcF;
    FILE_FUNC* dstF = sync_info->dstF;

    src_fd = srcF->initialize(srcp);
    dst_fd = dstF->initialize(dstp);
    if(src_fd < 0 || dst_fd < 0) {
        return 1;
    }

    struct stat src_stat;
    struct stat dst_stat;

    if(srcF->_stat(src_fd, srcp, &src_stat, 1)) {
        goto error;
    }

    int src_dir = srcF->is_dir(srcp, &src_stat);

    if(src_dir == -1) {
        print_error(SDB_MESSAGE_ERROR, ERR_SYNC_COPY_FAIL, F(ERR_SYNC_NOT_FILE, srcp));
        goto error;
    }

    int dst_dir = 0;

    if(!dstF->_stat(dst_fd, dstp, &dst_stat, 0)) {
        dst_dir = dstF->is_dir(dstp, &dst_stat);
    }
    else{
        int dst_len = strlen(dstp);
        if( dstp[dst_len - 1] == '/' || dstp[dst_len - 1] == '\\') {
            dst_dir = 1;
        }
    }

    if(dst_dir == -1) {
        print_error(SDB_MESSAGE_ERROR, ERR_SYNC_COPY_FAIL, F(ERR_SYNC_NOT_FILE, dstp));
        goto error;
    }

    if(src_dir == 0) {
        /* if we're copying a local file to a remote directory,
        ** we *really* want to copy to remotedir + "/" + localfilename
        */
        char full_dstpath[PATH_MAX];
        if(dst_dir == 1) {
            char* src_filename = get_filename(srcp);
            append_file(full_dstpath, dstp, src_filename, PATH_MAX);

            if(is_utf8 != 0) {
                dstp = ansi_to_utf8(full_dstpath);
            }
            else {
                dstp = full_dstpath;
            }
        }
        COPY_INFO copy_info;
        copy_info.src = srcp;
        copy_info.dst = dstp;
        copy_info._stat = src_stat;
        if(!file_copy(src_fd, dst_fd, &copy_info, sync_info)) {
            sync_info->copied++;
        }
        else {
            goto error;
        }
    }
    //copy directory
    else {
        LIST_NODE* dir_list = NULL;
        //for free later, do strncpy
        int len = strlen(srcp);
        char* _srcp = (char*)malloc(sizeof(char)*len + 1);
        s_strncpy(_srcp, srcp, len+1);

        len = strlen(dstp);
        char* _dstp = (char*)malloc(sizeof(char)*len + 1);
        s_strncpy(_dstp, dstp, len+1);

        COPY_INFO* __info;
        create_copy_info(&__info, _srcp, _dstp, &src_stat);
        append(&dir_list, __info);

        while(dir_list != NULL) {
            LIST_NODE* entry_list = NULL;
            COPY_INFO* _info = (COPY_INFO*)dir_list->data;

            if(srcF->get_dirlist(src_fd, _info->src, _info->dst, &entry_list, sync_info)) {
                fprintf(stdout,"skipped: %s -> %s\n", _info->src, _info->dst);
                sync_info->skipped++;
                free_list(entry_list, NULL);
                remove_first(&dir_list, free_copyinfo);
                continue;
            }
            remove_first(&dir_list, free_copyinfo);
            LIST_NODE* curptr = entry_list;

            while(curptr != NULL) {
                COPY_INFO* copy_info = (COPY_INFO*)curptr->data;
                curptr = curptr->next_ptr;
                char* src_p = (char*)copy_info->src;
                char* dst_p = (char*)copy_info->dst;

                src_dir = srcF->is_dir(src_p, &(copy_info->_stat));
                if(src_dir < 0) {
                    print_error(SDB_MESSAGE_ERROR, ERR_SYNC_COPY_FAIL, F(ERR_SYNC_NOT_FILE, src_p));
                    goto skip_in;
                }
                if(src_dir == 1) {
                    append(&dir_list, copy_info);
                    D("copy destination info =  %s\n", copy_info->dst);
                    continue;
                }
                else {
                    if(!file_copy(src_fd, dst_fd, copy_info, sync_info)) {
                        sync_info->copied++;
                        SAFE_FREE(copy_info);
                        SAFE_FREE(src_p);
                        SAFE_FREE(dst_p);
                        continue;
                    }
                }
skip_in:
                fprintf(stdout,"skipped: %s -> %s\n", src_p, dst_p);
                sync_info->skipped++;
                SAFE_FREE(copy_info);
                SAFE_FREE(src_p);
                SAFE_FREE(dst_p);
            }
            free_list(entry_list, no_free);
        }
    }

    fprintf(stdout,"%d file(s) %s. %d file(s) skipped.\n",
            sync_info->copied, sync_info->tag, sync_info->skipped);

    long long end_time = NOW() - start_time;

    if(end_time != 0) {
        fprintf(stdout,"%-30s   %lldKB/s (%lld bytes in %lld.%03llds)\n",
                srcp,
                ((((long long) sync_info->total_bytes) * 1000000LL) / end_time) / 1024LL,
                (long long) sync_info->total_bytes, (end_time / 1000000LL), (end_time % 1000000LL) / 1000LL);
    }

    finalize(src_fd, dst_fd, sync_info);
    return 0;

error:
    finalize(src_fd, dst_fd, sync_info);
    return 1;
}
