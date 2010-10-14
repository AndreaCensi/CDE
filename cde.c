// tested on x86-Linux
// Inspired by tutorials:
//   http://www.linuxjournal.com/article/6100?page=0,1

#include "cde.h"

int main(int argc, char* argv[]) {
  pid_t child_pid;
  int status;

  if (argc <= 1) {
    fprintf(stderr, "Error: empty command\n");
    exit(1);
  }

  child_pid = fork();

  if (child_pid == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    char** target_program_argv = argv + 1;
    execvp(target_program_argv[0], target_program_argv);

    /* If execv returns, it must have failed. */
    fprintf(stderr, "Unknown command %s\n", target_program_argv[0]);
    exit(1);
  }
  else if (child_pid < 0) {
    fprintf(stderr, "Error: fork failed\n");
    exit(1);
  }
  else {
    char filename[255]; // hope this is big enough!
    char open_mode;

    // create a fresh pcb and populate some of its fields:
    struct pcb child_pcb;
    memset(&child_pcb, 0, sizeof(child_pcb));
    child_pcb.pid = child_pid;
    child_pcb.state = INUSER;

    while (1) {
      wait(&status);
      if (WIFEXITED(status)) {
        break;
      }

      long orig_eax, eax;
      orig_eax = ptrace(PTRACE_PEEKUSER, child_pcb.pid, 4 * ORIG_EAX, NULL);

      if (orig_eax == SYS_open) {
        if (child_pcb.state == INUSER) { /* Syscall entry */
          child_pcb.state = INCALL;

          // filename is a pointer in the child process's address space
          char* child_filename = (char*)ptrace(PTRACE_PEEKUSER, child_pcb.pid, 4 * EBX, NULL);
          long open_flags = ptrace(PTRACE_PEEKUSER, child_pcb.pid, 4 * ECX, NULL);
          open_mode = (open_flags & 0x3);

          // TODO: could create a strcpy to optimize, since most filenames
          // aren't long, so we can bail on the first NULL
          memcpy_from_child(&child_pcb, filename, child_filename, 255);
        }
        else { /* Syscall exit */
          eax = ptrace(PTRACE_PEEKUSER, child_pcb.pid, 4 * EAX, NULL);

          switch (open_mode) {
            case O_RDONLY:
              printf("open('%s', 'r') = %ld\n", filename, eax);
              break;
            case O_WRONLY:
              printf("open('%s', 'w') = %ld\n", filename, eax);
              break;
            case O_RDWR:
              printf("open('%s', 'rw') = %ld\n", filename, eax);
              break;
          }

          child_pcb.state = INUSER;
        }
      }

      ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    }
  }

  return 0;
}
