// Lots of code stolen from Goanna

#include "cde.h"


// inject a system call to child (victim) process to tell it to attach
// our shared memory segment

/* Setup a shared memory region within our victim process, then repeat the current system call. */
void setup_shmat(struct pcb* pcb) {
  int ret;

  // stash away original registers so that we can restore them later
  memcpy(&pcb->orig_regs, &pcb->regs, sizeof(pcb->orig_regs));

  pcb->state = INSHMAT;

  /* The return value is actually stored in the victim address space. */
  pcb->savedaddr = find_free_addr(pcb->pid, PROT_READ|PROT_WRITE, sizeof(int));
  pcb->savedword = ptrace(PTRACE_PEEKDATA, pcb->pid, pcb->savedaddr, 0);
  if (errno) {
    fprintf(stderr, "Can not peek at free address for %d in setup_shmat: %s\n", pcb->pid, strerror(errno));
    sleep(100);
    exit(1);
  }

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
                                           victim's address space. */
  pcb->regs.edi = (long)NULL; /* We don't use shmat's shmaddr */
  pcb->regs.ebp = 0; /* The "fifth" argument is unused. */

  ret = ptrace(PTRACE_SETREGS, pcb->pid, NULL, &pcb->regs);
  if (ret < 0) {
    fprintf(stderr, "%s: Could not set new registers for %d: %s\n",
        __FUNCTION__, pcb->pid, __FILE__);
    exit(1);
  }
}


int main(int argc, char* argv[]) {
  pid_t child_pid;
  int status;
  int ret;

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
    // TODO: add as a new field in 'struct pcb'
    char filename[255]; // hope this is big enough!
    char open_mode;

    // create a fresh pcb and populate some of its fields:
    struct pcb* child_pcb = new_pcb(child_pid, INUSER);
    assert(child_pcb);

    while (1) {
      pid_t pid = waitpid(child_pcb->pid, &status, __WALL);
      assert(pid == child_pcb->pid);

      if (WIFEXITED(status)) {
        break;
      }

      ret = ptrace(PTRACE_GETREGS, child_pcb->pid, NULL, &child_pcb->regs);
      if (ret < 0) {
        fprintf(stderr, "ptrace getregs (pid = %d) at invocation: %s\n",
            child_pcb->pid, strerror(errno));
        exit(1);
      }

      //printf("state: %d\n", child_pcb->state);

      switch (child_pcb->state) {
        case INUSER:
          child_pcb->state = INCALL;

          if (child_pcb->regs.orig_eax == SYS_open) {
            // only do this ONCE per pcb on-demand
            if (!child_pcb->victimshm) {
              setup_shmat(child_pcb);
              ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL);
              break;
            }

            // filename is a pointer in the child process's address space
            char* child_filename = (char*)child_pcb->regs.ebx;
            long open_flags = child_pcb->regs.ecx;
            open_mode = (open_flags & 0x3);

            // TODO: could create a strcpy to optimize, since most filenames
            // aren't long, so we can bail on the first NULL
            memcpy_from_child(child_pcb, filename, child_filename, 255);

            // try to redirect it to "/home/pgbovine/home_test.txt"
            if (strcmp(filename, "infile.txt") == 0) {
              strcpy(child_pcb->localshm, "/home/pgbovine/home_test.txt");
              printf("shm = '%s'\n", child_pcb->localshm);

              // redirect the system call to the new path
              // TODO: should we restore ebx back to its original value
              // after we're done?
              child_pcb->regs.ebx = (long)child_pcb->victimshm;
              ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs);
            }
            else if (strcmp(filename, "/usr/lib/libpython2.5.so.1.0") == 0) {
              strcpy(child_pcb->localshm, "/home/pgbovine/ptrace-test/libs/libpython2.5.so.1.0");

              printf("shm = '%s'\n", child_pcb->localshm);
              child_pcb->regs.ebx = (long)child_pcb->victimshm;
              ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs);
            }
          }

          status = ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL);
          if (status < 0) {
            fprintf (stderr, "Could not tell child to continue executing the syscall.\n");
            exit(1);
          }
          break;

        case INSHMAT:

          if (child_pcb->regs.eax != 0) {
            fprintf(stderr, "Could not attach shared memory in the victim: %s\n",
                    strerror(-child_pcb->regs.eax));
            exit(1);
          }

          errno = 0;
          child_pcb->victimshm = (void*)ptrace(PTRACE_PEEKDATA,
                                               child_pcb->pid, child_pcb->savedaddr, 0);
          if (errno) {
            perror("Can not peek at shmat return");
            exit(1);
          }

          ret = ptrace(PTRACE_POKEDATA,
                       child_pcb->pid, child_pcb->savedaddr, child_pcb->savedword);
          if (ret) {
            perror("Can not poke to restore savedword");
            exit(1);
          }

          memcpy(&child_pcb->regs, &child_pcb->orig_regs, sizeof(child_pcb->regs));
          child_pcb->regs.eax = child_pcb->regs.orig_eax;

          child_pcb->regs.eip = child_pcb->orig_regs.eip - 2;
          ret = ptrace(PTRACE_SETREGS, child_pcb->pid, NULL, &child_pcb->regs);
          if (ret < 0) {
            fprintf(stderr, "Could not setup new registers on forced return.\n");
            exit(1);
          }

          assert(child_pcb->victimshm);

          child_pcb->state = INUSER;
          ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL);
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
          ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL);
          break;

        default:
          assert(0);
      }
    }

    delete_pcb(child_pcb);
  }

  return 0;
}
