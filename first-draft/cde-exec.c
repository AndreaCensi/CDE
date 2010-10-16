// Lots of code stolen from Goanna

#include "cde.h"


// inject a system call in the child process to tell it to attach our
// shared memory segment, so that it can read modified paths from there

// Setup a shared memory region within child process, then repeat current system call
static void setup_shmat(struct pcb* pcb) {
  // stash away original registers so that we can restore them later
  memcpy(&pcb->orig_regs, &pcb->regs, sizeof(pcb->orig_regs));

  pcb->state = INSHMAT;

  // The return value of shmat (attached address) is actually stored in
  // the child's address space
  pcb->savedaddr = find_free_addr(pcb->pid, PROT_READ|PROT_WRITE, sizeof(int));
  pcb->savedword = ptrace(PTRACE_PEEKDATA, pcb->pid, pcb->savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  /* The shmat call is implemented as a godawful sys_ipc. */
  pcb->regs.orig_eax = __NR_ipc;
  /* The parameters are passed in ebx, ecx, edx, esi, edi, and ebp */
  pcb->regs.ebx = SHMAT;
  /* The kernel names the rest of these, first, second, third, ptr,
   * and fifth. Only first, second and ptr are used as inputs.  Third
   * is a pointer to the output (unsigned long).
   */
  pcb->regs.ecx = pcb->shmid;
  pcb->regs.edx = 0; /* shmat flags */
  pcb->regs.esi = (long)pcb->savedaddr; /* Pointer to the return value in the
                                           child's address space. */
  pcb->regs.edi = (long)NULL; /* We don't use shmat's shmaddr */
  pcb->regs.ebp = 0; /* The "fifth" argument is unused. */

  EXITIF(ptrace(PTRACE_SETREGS, pcb->pid, NULL, &pcb->regs) < 0);
  EXITIF(ptrace(PTRACE_SYSCALL, pcb->pid, NULL, NULL) < 0); // keep listening
}


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
            // only do this ONCE on-demand
            if (!child_pcb->childshm) {
              setup_shmat(child_pcb);
              break;
            }

            // filename is a pointer in the child process's address space
            char* child_filename = (char*)child_pcb->regs.ebx;
            long open_flags = child_pcb->regs.ecx;
            open_mode = (open_flags & 0x3);

            // TODO: could create a strcpy to optimize, since most filenames
            // aren't long, so we can bail on the first NULL
            memcpy_from_child(child_pcb, filename, child_filename, 255);

            if (strcmp(filename, "infile.txt") == 0) {
              strcpy(child_pcb->localshm, "infile2.txt");
              printf("shm = %p %p\n", child_pcb->localshm, child_pcb->childshm);

              // redirect the system call to the new path
              // TODO: should we restore ebx back to its original value
              // after we're done?
              child_pcb->regs.ebx = (long)child_pcb->childshm;
              ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs);
            }
            else if (strcmp(filename, "/usr/lib/libpython2.5.so.1.0") == 0) {
              strcpy(child_pcb->localshm, "/home/pgbovine/ptrace-test/libs/libpython2.5.so.1.0");

              printf("shm = '%s'\n", child_pcb->localshm);
              child_pcb->regs.ebx = (long)child_pcb->childshm;
              ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs);
            }
          }

          EXITIF(ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL) < 0);
          break;

        case INSHMAT:
          assert(child_pcb->regs.eax == 0);

          errno = 0;
          child_pcb->childshm = (void*)ptrace(PTRACE_PEEKDATA,
                                              child_pcb->pid, child_pcb->savedaddr, 0);
          EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

          EXITIF(ptrace(PTRACE_POKEDATA,
                        child_pcb->pid, child_pcb->savedaddr, child_pcb->savedword));

          memcpy(&child_pcb->regs, &child_pcb->orig_regs, sizeof(child_pcb->regs));
          child_pcb->regs.eax = child_pcb->regs.orig_eax;

          // back up IP so that we can re-execute previous instruction
          child_pcb->regs.eip = child_pcb->orig_regs.eip - 2;
          EXITIF(ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs) < 0);

          assert(child_pcb->childshm);

          child_pcb->state = INUSER;
          EXITIF(ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL) < 0);
          break;

        case INCALL:
          if (child_pcb->regs.orig_eax == SYS_open) {
            switch (open_mode) {
              case O_RDONLY:
                printf("  open('%s', 'r') = %ld\n", filename, child_pcb->regs.eax);
                break;
              case O_WRONLY:
                printf("  open('%s', 'w') = %ld\n", filename, child_pcb->regs.eax);
                break;
              case O_RDWR:
                printf("  open('%s', 'rw') = %ld\n", filename, child_pcb->regs.eax);
                break;
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

