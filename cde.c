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

    // If execv returns, it must have failed
    fprintf(stderr, "Unknown command %s\n", target_program_argv[0]);
    exit(1);
  }
  else if (child_pid < 0) {
    fprintf(stderr, "Error: fork failed\n");
    exit(1);
  }
  else {
    // TODO: add as a new field in 'struct pcb'
    char filename[255]; // hope this is big enough!
    char open_mode;

    struct pcb* child_pcb = new_pcb(child_pid, INUSER);
    assert(child_pcb);

    while (1) {
      pid_t pid = waitpid(child_pcb->pid, &status, __WALL);
      assert(pid == child_pcb->pid);

      if (WIFEXITED(status)) {
        break;
      }

      // populates child_pcb->regs
      EXITIF(ptrace(PTRACE_GETREGS, child_pcb->pid, NULL, &child_pcb->regs) < 0);

      switch (child_pcb->state) {
        case INUSER:
          child_pcb->state = INCALL;

          if (child_pcb->regs.orig_eax == SYS_open) {
            // filename is a pointer in the child process's address space
            char* child_filename = (char*)child_pcb->regs.ebx;
            long open_flags = child_pcb->regs.ecx;
            open_mode = (open_flags & 0x3);

            // TODO: could create a strcpy to optimize, since most filenames
            // aren't long, so we can bail on the first NULL
            memcpy_from_child(child_pcb, filename, child_filename, 255);
          }

          EXITIF(ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL) < 0);
          break;

        case INCALL:
          if (child_pcb->regs.orig_eax == SYS_open) {
            // a non-negative return value means that a VALID file
            // descriptor was returned (i.e., the file actually exists)
            // only grab info for files opened in read mode
            if ((child_pcb->regs.eax >= 0) &&
                (open_mode == O_RDONLY || open_mode == O_RDWR)) {
              struct stat st;
              EXITIF(stat(filename, &st));
              // check whether it's a REGULAR-ASS file
              if (S_ISREG(st.st_mode)) {
                printf("  open('%s') = %ld\n", filename, child_pcb->regs.eax);
              }
            }
          }

          child_pcb->state = INUSER;
          EXITIF(ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL) < 0);
          break;

        default:
          assert(0);
          break;
      }
    }

    delete_pcb(child_pcb);
  }

  return 0;
}

