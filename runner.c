#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#ifndef __APPLE__
#include <seccomp.h>
#else
#warning "###### This judger can not work under OSX, installation is only for dev dependencies! #####"
#endif
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "runner.h"
#include "logger.h"

#define STACK_SIZE (2 * 1024 * 1024)


int child_process(void *child_process_args){
    FILE *log_fp = ((struct child_process_args *)child_process_args)->log_fp;
    struct config *config = ((struct child_process_args *)child_process_args)->config;
    FILE *in_file = NULL, *out_file = NULL, *err_file = NULL;
    struct rlimit memory_limit, cpu_time_rlimit;
#ifndef __APPLE__
    int i;
    int syscall_whitelist[] = {SCMP_SYS(read), SCMP_SYS(fstat),
                                SCMP_SYS(mmap), SCMP_SYS(mprotect), 
                                SCMP_SYS(munmap), SCMP_SYS(open), 
                                SCMP_SYS(arch_prctl), SCMP_SYS(brk), 
                                SCMP_SYS(access), SCMP_SYS(exit_group), 
                                SCMP_SYS(close)};
    int syscall_whitelist_length = sizeof(syscall_whitelist) / sizeof(int);
    scmp_filter_ctx ctx = NULL;
#endif
    // child process
    // On success, these system calls return 0.
    // On error, -1 is returned, and errno is set appropriately.
    if (config->max_memory != MEMORY_UNLIMITED) {
        memory_limit.rlim_cur = memory_limit.rlim_max = (rlim_t) (config->max_memory) * 2;
        if (setrlimit(RLIMIT_AS, &memory_limit) == -1) {
            LOG_FATAL(log_fp, "setrlimit memory failed, errno: %d", errno);
            ERROR(log_fp, SETRLIMIT_FAILED);
        }
    }
    if (config->max_cpu_time != CPU_TIME_UNLIMITED) {
        // we do not use setitimer to limit cpu/real time anymore
        // because timer signal can be caught by process and 
        // timer can be cancelled/changed if there is no syscall filter
        // none root can not change setrlimit hard limit
        // another reason is child process can not inherit timeout rules from parent process defined by setitimer,
        // but setrlimit rule can be inherited
        cpu_time_rlimit.rlim_cur = cpu_time_rlimit.rlim_max = (config->max_cpu_time + 1000) / 1000;
        if (setrlimit(RLIMIT_CPU, &cpu_time_rlimit) == -1) {
            LOG_FATAL(log_fp, "setrlimit cpu time failed, errno: %d", errno);
            ERROR(log_fp, SETRLIMIT_FAILED);
        }
    }

    // read stdin from in file
    // On success, these system calls return the new descriptor. 
    // On error, -1 is returned, and errno is set appropriately.
    if (config->in_file != NULL) {
        if ((in_file = fopen(config->in_file, "r")) == NULL) {
            LOG_FATAL(log_fp, "failed to open stdin redirect file");
            ERROR(log_fp, DUP2_FAILED);
        }
        if (dup2(fileno(in_file), fileno(stdin)) == -1) {
            LOG_FATAL(log_fp, "dup2 stdin failed, errno: %d", errno);
            ERROR(log_fp, DUP2_FAILED);
        }
    }
    // write stdout to out file
    if (config->out_file != NULL) {
        if ((out_file = fopen(config->out_file, "w")) == NULL) {
            LOG_FATAL(log_fp, "failed to open stdout redirect file");
            ERROR(log_fp, DUP2_FAILED);
        }
        if (dup2(fileno(out_file), fileno(stdout)) == -1) {
            LOG_FATAL(log_fp, "dup2 stdout failed, errno: %d", errno);
            ERROR(log_fp, DUP2_FAILED);
        }
    }
    // write stderr to err file
    if (config->err_file != NULL) {
        // if err_file and out_file are the same path, we use out_file pointer as err_file pointer, to avoid conflict
        if (strcmp(config->out_file, config->err_file) == 0) {
            err_file = out_file;
        }
        else {
            if ((err_file = fopen(config->err_file, "w")) == NULL) {
                LOG_FATAL(log_fp, "failed to open stderr redirect file");
                ERROR(log_fp, DUP2_FAILED);
            }
        }
        if (dup2(fileno(err_file), fileno(stderr)) == -1) {
            LOG_FATAL(log_fp, "dup2 stdout failed, errno: %d", errno);
            ERROR(log_fp, DUP2_FAILED);
        }
    }
    if (config->gid != -1 && setgid(config->gid) == -1) {
        LOG_FATAL(log_fp, "setgid failed, errno: %d", errno);
        ERROR(log_fp, SET_GID_FAILED);
    }
    if (config->uid != -1 && setuid(config->uid) == -1) {
        LOG_FATAL(log_fp, "setuid failed, errno: %d", errno);
        ERROR(log_fp, SET_UID_FAILED);
    }
#ifndef __APPLE__
    if (config->use_sandbox != 0) {
        // load seccomp rules
        ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
            LOG_FATAL(log_fp, "init seccomp failed");
            ERROR(log_fp, LOAD_SECCOMP_FAILED);
        }
        for (i = 0; i < syscall_whitelist_length; i++) {
            if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_whitelist[i], 0) != 0) {
                LOG_FATAL(log_fp, "load syscall white list failed");
                ERROR(log_fp, LOAD_SECCOMP_FAILED);
            }
        }
        // add extra rule for execve
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, config->path)) != 0) {
            LOG_FATAL(log_fp, "load execve rule failed");
            ERROR(log_fp, LOAD_SECCOMP_FAILED);
        }
        // only fd 0 1 2 are allowed
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_LE, 2)) != 0) {
            LOG_FATAL(log_fp, "load dup2 rule failed");
            ERROR(log_fp, LOAD_SECCOMP_FAILED);
        }
        if (seccomp_load(ctx) != 0) {
            LOG_FATAL(log_fp, "seccomp load failed");
            ERROR(log_fp, LOAD_SECCOMP_FAILED);
        }
        seccomp_release(ctx);
    }
#endif
    execve(config->path, config->args, config->env);
    LOG_FATAL(log_fp, "execve failed, errno: %d", errno);
    ERROR(log_fp, EXCEVE_FAILED);
    return 1;
}


int kill_pid(pid_t pid) {
    return kill(pid, SIGKILL);
}


void *timeout_killer(void *timeout_killer_args) {
    // this is a new thread, kill the process if timeout
    FILE *log_fp = ((struct timeout_killer_args *)timeout_killer_args)->log_fp;
    pid_t pid = ((struct timeout_killer_args *)timeout_killer_args)->pid;
    int timeout = ((struct timeout_killer_args *)timeout_killer_args)->timeout;
    // On success, pthread_detach() returns 0; on error, it returns an error number.
    if (pthread_detach(pthread_self()) != 0) {
        LOG_FATAL(log_fp, "pthread_detach failed");
        kill_pid(pid);
        return NULL;
    }
    // usleep can't be used, time args must < 1000ms
    // this may sleep longer that expected, but we will have a check at the end
    if (sleep((timeout + 1000) / 1000) != 0) {
        LOG_FATAL(log_fp, "sleep failed");
        kill_pid(pid);
        return NULL;
    }
    if (kill(pid, SIGKILL) != 0) {
        LOG_WARNING(log_fp, "kill failed, pid: %d", pid);
        return NULL;
    }
    LOG_DEBUG(log_fp, "pid %d is killed", pid);
    return NULL;
}
    

void run(struct config *config, struct result *result) {
    int status;
    struct rusage resource_usage;
    struct timeval start, end;
    
    int signal;
    pid_t pid;
    pthread_t tid;
    FILE *log_fp = NULL;
    char *stack = NULL;
    struct child_process_args child_process_args;
    struct timeout_killer_args timeout_killer_args;
    
    log_fp = log_open(config->log_path);
    if(log_fp == NULL){
        result->flag = SYSTEM_ERROR;
        return;
    }

    gettimeofday(&start, NULL);

    if(config->max_memory < 1 && config->max_memory != MEMORY_UNLIMITED) {
        LOG_FATAL(log_fp, "max_memory must > 1 or unlimited");
        result->flag = SYSTEM_ERROR;
        log_close(log_fp);
        return;
    }
    if(config->max_cpu_time < 1 && config->max_cpu_time != CPU_TIME_UNLIMITED) {
        LOG_FATAL(log_fp, "max_cpu_time must > 1 or unlimited");
        result->flag = SYSTEM_ERROR;
        log_close(log_fp);
        return;
    }
    else if (config->max_cpu_time != CPU_TIME_UNLIMITED && config->max_real_time < 1) {
            LOG_FATAL(log_fp, "max_real_time must be set when max_cpu_time is set");
            result->flag = SYSTEM_ERROR;
            log_close(log_fp);
            return;
    }
    if((stack = malloc(STACK_SIZE)) == NULL) {
        LOG_FATAL(log_fp, "malloc stack failed");
        result->flag = SYSTEM_ERROR;
        log_close(log_fp);
        return; 
    }

    child_process_args.config = config;
    child_process_args.log_fp = log_fp;
    pid = clone(child_process, stack + STACK_SIZE, SIGCHLD, (void *)(&child_process_args));

    if (pid < 0) {
        LOG_FATAL(log_fp, "clone failed");
        result->flag = SYSTEM_ERROR;
        log_close(log_fp);
        return;
    }
    else {
        // parent process
        if (config->max_cpu_time != CPU_TIME_UNLIMITED) {
            // start a new thread to watch real time
            timeout_killer_args.pid = pid;
            timeout_killer_args.timeout = config->max_real_time;
            timeout_killer_args.log_fp = log_fp;
            if (pthread_create(&tid, NULL, timeout_killer, (void *) (&timeout_killer_args)) != 0) {
                LOG_FATAL(log_fp, "pthread_create failed");
                result->flag = SYSTEM_ERROR;
                // parent process can not exit now, or child process will become zombie
            }
        }

        // on success, returns the process ID of the child whose state has changed;
        // On error, -1 is returned.
        if (wait4(pid, &status, 0, &resource_usage) == -1) {
            LOG_FATAL(log_fp, "wait4 failed");
            result->flag = SYSTEM_ERROR;
            log_close(log_fp);
            return;
        }
        // process exited, we may need to cancel timeout killer thread
        if (config->max_cpu_time != CPU_TIME_UNLIMITED) {
            if (pthread_cancel(tid) != 0) {
                LOG_WARNING(log_fp, "pthread_cancel failed");
            };
        }
        LOG_DEBUG(log_fp, "exit status: %d", WEXITSTATUS(status));
        result->exit_status = WEXITSTATUS(status);
        result->cpu_time = (int) (resource_usage.ru_utime.tv_sec * 1000 +
                                  resource_usage.ru_utime.tv_usec / 1000 +
                                  resource_usage.ru_stime.tv_sec * 1000 +
                                  resource_usage.ru_stime.tv_usec / 1000);
         // avoid 0 ms
        if(result->cpu_time == 0) {
            result->cpu_time = 1;
        }

        // osx: ru_maxrss the maximum resident set size utilized (in bytes).
        // linux: ru_maxrss (since Linux 2.6.32)This  is  the  maximum  resident set size used (in kilobytes).
        // For RUSAGE_CHILDREN, this is the resident set size of the largest child,
        // not the maximum resident set size of the processtree.
        result->memory = resource_usage.ru_maxrss * 1024;

        result->signal = 0;
        result->flag = SUCCESS;

        if (WEXITSTATUS(status) != 0) {
            result->flag = RUNTIME_ERROR;
        }
        // if signaled
        if (WIFSIGNALED(status) != 0) {
            signal = WTERMSIG(status);
            LOG_DEBUG(log_fp, "signal: %d", signal);
            result->signal = signal;
            if (signal == SIGALRM) {
                result->flag = REAL_TIME_LIMIT_EXCEEDED;
            }
            else if (signal == SIGVTALRM) {
                result->flag = CPU_TIME_LIMIT_EXCEEDED;
            }
            // Child process error
            else if (signal == SIGUSR1){
                result->flag = SYSTEM_ERROR;
            }
            else {
                result->flag = RUNTIME_ERROR;
            }
        }
        
        if (config->max_memory != MEMORY_UNLIMITED && result->memory > config->max_memory) {
            result->flag = MEMORY_LIMIT_EXCEEDED;
        }
        
        gettimeofday(&end, NULL);
        result->real_time = (int) (end.tv_sec * 1000 + end.tv_usec / 1000 - start.tv_sec * 1000 - start.tv_usec / 1000);
        if (result->real_time > config->max_real_time) {
            result->flag = REAL_TIME_LIMIT_EXCEEDED;
        }
        if(result->cpu_time > config->max_cpu_time) {
            result->flag = CPU_TIME_LIMIT_EXCEEDED;
        }
        log_close(log_fp);
    }
}
