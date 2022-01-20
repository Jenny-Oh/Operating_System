#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "process.h"
#include "filesys/off_t.h"

struct file{
    struct inode *inode;
    off_t pos;
    bool deny_write;
};



static void syscall_handler (struct intr_frame *);
void is_valid_addr(const void*);
void is_valid_fd(int fd);
struct lock cur_lock;

void
syscall_init (void) 
{
    lock_init(&cur_lock);
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!=>");

  //printf("sys => %u\n",*(uint32_t*)(f->esp));
  
  void* addr = f->esp;
  void* a,*b,*c,*d;
  //printf("%u     ",(int)*(uint32_t*)addr);  
  switch(*(uint32_t*)(addr)) {
    case SYS_HALT: // 0 
        halt();
        break;
    case SYS_EXIT: // 1
        is_valid_addr(addr+4);
        exit(*(uint32_t*)(addr+4));
        break;
    case SYS_EXEC: //2
        is_valid_addr(addr+4);
        //printf("########exec\n");
        f->eax = exec((const char*)*(uint32_t*)(addr+4));
        break;
    case SYS_WAIT: //3
        is_valid_addr(addr+4);
        f->eax = wait((pid_t)*(uint32_t*)(addr+4));
        break;
    case SYS_READ://8
        c = addr+12; b = addr+8; a = addr+4;
        is_valid_addr(a); 
        is_valid_addr(b);
        is_valid_addr(c);
        //hex_dump(addr,addr,PHYS_BASE - addr,1);
        //printf("fd = %s\n", (char*)*(uint32_t*)(b));
        f->eax = read((int)*(uint32_t*)(a),(void*)*(uint32_t*)(b),(unsigned)*(uint32_t*)(c));
        break;
    case SYS_WRITE://9
        c = addr+12; b = addr+8; a = addr+4;
        is_valid_addr(a); 
        is_valid_addr(b);
        is_valid_addr(c);
        //printf("fd = %s\n", (char*)*(uint32_t*)(b));
        f->eax = write((int)*(uint32_t*)(a),(const void*)*(uint32_t*)(b),(unsigned)*(uint32_t*)(c));
        //f->eax = write((int)*(uint32_t*)(addr+20),(const void*)*(uint32_t*)(addr+24),(unsigned)*(uint32_t*)(addr+28));
        break;
    case SYS_FIBO://13
        is_valid_addr(addr+4);
        //printf("")
        //printf("size = %d\n", (int)*(uint32_t*)(addr+28));
        f->eax = fibonacci((int)*(uint32_t*)(addr+4));        
        break;
    case SYS_MAX://14
        d = addr + 16; c = d - 4; b = c - 4; a = b - 4; 
        is_valid_addr(a); 
        is_valid_addr(b);
        is_valid_addr(c);
        is_valid_addr(d);
        f->eax = max_of_four_int((int)*(uint32_t*)(a),(int)*(uint32_t*)(b),(int)*(uint32_t*)(c),(int)*(uint32_t*)(d));
        break;
    case SYS_CREATE: //4
        is_valid_addr(addr+4);
        is_valid_addr(addr+8);
        f->eax = create((char*)*(uint32_t*)(addr+4),(unsigned)*(uint32_t*)(addr+8));
        break;
    case SYS_REMOVE: //5
        is_valid_addr(addr+4);
        f->eax = remove((char*)*(uint32_t*)(addr+4));
        break;
    case SYS_OPEN: //6
        is_valid_addr(addr+4);
        
        f->eax = open((char*)*(uint32_t*)(addr+4));
        break;
    case SYS_CLOSE://12
        is_valid_addr(addr+4);
        close((int)*(uint32_t*)(addr+4));
        break;
    case SYS_FILESIZE: //7
        is_valid_addr(addr+4);
        f->eax = filesize((int)*(uint32_t*)(addr+4));
        break;
    case SYS_SEEK: //10
        is_valid_addr(addr+4);
        is_valid_addr(addr+8);
        seek((int)*(uint32_t*)(addr+4), (unsigned)*(uint32_t*)(addr+8));
        break;
    case SYS_TELL: //11
        is_valid_addr(addr+4);
        f->eax = tell((int)*(uint32_t*)(addr+4));
        break;
  }
  //thread_exit ();
}

/* Project 1 */
void is_valid_addr(const void *addr){
    if (!is_user_vaddr(addr))
        exit(-1);
}


void halt(void){
    shutdown_power_off();
}

void exit(int status){
    struct thread *t = thread_current();
    /*
    int length = strlen(t->name)+1; 
void is_valid_fd(int fd){
    char cur[length];
    strlcpy(cur,t->name,length);
    */
    printf("%s: exit(%d)\n",t->name,status);
    t->exit_status = status;
    t->parent->exit_status = status;
    for (int i = 3; i <128; i++) {
        if(t->fd[i] != NULL)
            close(i);
    }
    
   

    thread_exit();
}

pid_t exec (const char* file){
    //printf("current execution %s \n", file);
    return process_execute(file);
}

int wait(pid_t pid){
    //printf("pid wait %d\n",pid);
    return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size){
    is_valid_addr(buffer);
    lock_acquire(&cur_lock);
    //int ret_size = 0;
    if (fd == 0){ //STDIN
        for (int i = 0; i< (int)size; i++)
            *(uint8_t*)(buffer+i) = input_getc();
        lock_release(&cur_lock);
        return size;
        //printf("read context : %s\n", (uint8_t*)buffer);
    }
    else if(fd >= 3){
        //lock_acquire(&cur_lock);
        //off_t file_read(struct file* , void * buffer , off_t size);
        struct thread *t = thread_current();
        is_valid_fd(fd);
        struct file *f = t->fd[fd];
        if (f == NULL){
            lock_release(&cur_lock);
            exit(-1);
        }
        lock_release(&cur_lock);
        return file_read(f,buffer,size);

        //return size;
    }
    lock_release(&cur_lock);
    //return ret_size;
    return -1;
}

int write(int fd, const void *buffer, unsigned size){
    is_valid_addr(buffer);
    lock_acquire(&cur_lock); 
    if (fd == 1){ //STDOUT
        putbuf(buffer, size);
        lock_release(&cur_lock);
        return size;
    }
    else if (fd >= 3){
        //off_t file_write(struct file* , void * buffer, off_t size);
        struct thread *t = thread_current();
        is_valid_fd(fd);
        struct file* f = t->fd[fd];
        if (f == NULL){
            //lock_release(&cur_lock);
            exit(-1);
        }
        if (f->deny_write){
            file_deny_write(f);
            //exit(-1);

        }
        lock_release(&cur_lock);
        return file_write(f,buffer,(off_t)size);
        
    } 
    lock_release(&cur_lock);
    return -1;
}

/* NEW functions */

int fibonacci(int n){
    if (n==1 || n==2){
        return 1;
    }
    else{
        return fibonacci(n-2)+fibonacci(n-1);
    }
}

int max_of_four_int(int a, int b, int c, int d){
    int max = a;
    if (b > max)
        max = b;
    if (c > max)
        max = c;
    if (d > max)
        max = d;
    return max;
}

/* Project 2 */

void is_valid_fd(int fd){
    struct thread *t = thread_current();
    struct file *fp = t->fd[fd];
    if(fp == NULL)
        exit(-1);
    return;    
}

bool create(const char *file, unsigned initial_size){
    /* creates a new file called "file" initially "initial_size" bytes in size.
       returns true if successful, false otehrwise.
       create a file but no opening it */
    //lock_acquire(&cur_lock); 
    if (file == NULL){
        exit(-1); 
    }
    bool ret =  filesys_create(file,initial_size);
    return ret;
}

bool remove(const char *file){
    /* deletes the file called "file". A file may be removed regardless of whether if it'
       s open or closed, and removing an open file doesn't close it. */
    //lock_acquire(&cur_lock); 
    if (file == NULL){
        //lock_release(&cur_lock);
        exit(-1); 
    }
    bool ret =  filesys_remove(file);
    //lock_release(&cur_lock);
    return ret;
}

int open(const char *file){
    /* return file descriptor (fd)   or -1 if the file could not be opened. 
        0 or 1 are reserved for the console => 0 : STDIN, 1 : STDOUT 
        this system call never returns either of these file descriptors. 
        When a single file is opend more than once, each open returns a new file descriptor. 
        Therefore, different file descriptors are closed independently in separate calls to close. */
    if (file == NULL)
       exit(-1); 
    int ret_fd =  -1;
    //is_valid_addr(file);
    lock_acquire(&cur_lock);
    struct file* f= filesys_open(file);
    
    if (f == NULL){
        lock_release(&cur_lock);
        return -1;
    }
    struct thread *t = thread_current();

    //if (!strcmp(t->name,file))
    //    file_deny_write(f);
    
    //lock_acquire(&cur_lock);
    
    for (int i = 3; i< 128; i++){
        if (t->fd[i] == NULL){
            if (!strcmp(t->name,file))
                file_deny_write(f);
            t->fd[i]=f;
            ret_fd = i;
            break;
        }
    }
    lock_release(&cur_lock);
    return ret_fd; 

}

void close (int fd){
    /* close file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one*/
    //file_close(struct file*);
    struct thread *t = thread_current();
    is_valid_fd(fd);
    struct file *fp = t->fd[fd];
    if(fp == NULL){
        exit(-1);
    }
    t->fd[fd] = NULL;
    file_close(fp);
}

int filesize (int fd) {
    /* returns the size, in bytes, of the file open as fd */
    struct thread *t = thread_current();
    int ret = file_length(t->fd[fd]);
    return ret;
}

void seek (int fd, unsigned position){
    /*changes the next byte to be read or written in open file fd to position, expressed in bytes form the beginning of the file. If read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros*/
    struct thread *t = thread_current();
    is_valid_fd(fd);
    struct file *fp = t->fd[fd];
    file_seek(fp ,(off_t)position);
}


unsigned tell (int fd){
    /* returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
    struct thread *t = thread_current();
    is_valid_fd(fd);

    struct file *fp = t->fd[fd];
    unsigned ret = (unsigned)file_tell(fp);
    return ret;
}
