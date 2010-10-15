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
      pid_t pid = waitpid(child_pcb->pid, &status, 0);
      //pid_t pid = waitpid(child_pcb->pid, &status, __WALL);
      assert(pid == child_pcb->pid);

      if (WIFEXITED(status)) {
        break;
      }

      // populates child_pcb->regs
      EXITIF(ptrace(PTRACE_GETREGS, child_pcb->pid, NULL, &child_pcb->regs) < 0);

      switch (child_pcb->state) {
        case INUSER:
          if (child_pcb->regs.orig_eax == SYS_open) {
            // filename is a pointer in the child process's address space
            char* child_filename = (char*)child_pcb->regs.ebx;
            long open_flags = child_pcb->regs.ecx;
            open_mode = (open_flags & 0x3);

            // TODO: could create a strcpy to optimize, since most filenames
            // aren't long, so we can bail on the first NULL
            memcpy_from_child(child_pcb, filename, child_filename, 255);
          }
          else if (child_pcb->regs.orig_eax == SYS_execve) {
            char* child_filename = (char*)child_pcb->regs.ebx;
            printf("execve %p %d\n", child_filename,
                   ptrace(PTRACE_PEEKUSER, child_pcb->pid, 0, NULL));
            //memcpy_from_child(child_pcb, filename, child_filename, 255);
            //open_mode = O_RDONLY;
          }


          child_pcb->state = INCALL;
          EXITIF(ptrace(PTRACE_SYSCALL, child_pcb->pid, NULL, NULL) < 0);
          break;

        case INCALL:
          if (child_pcb->regs.orig_eax == SYS_open) {
            // a non-negative return value means that a VALID file
            // descriptor was returned (i.e., the file actually exists)
            // also, only grab info for files opened in read mode
            if ((child_pcb->regs.eax >= 0) &&
                (open_mode == O_RDONLY || open_mode == O_RDWR)) {
              struct stat st;
              EXITIF(stat(filename, &st));
              // check whether it's a REGULAR-ASS file
              if (S_ISREG(st.st_mode)) {
                // assume that relative paths are in working directory,
                // so no need to grab those files
                //
                // TODO: this isn't a perfect assumption since a
                // relative path could be something like '../data.txt',
                // which this won't pick up :)
                //   WOW, this libc function seems useful for
                //   canonicalizing filenames:
                //     char* canonicalize_file_name (const char *name)
                if (filename[0] == '/') {
                  // modify filename so that it appears as a RELATIVE PATH
                  // within a cde-root/ sub-directory
                  char* rel_path = malloc(strlen(filename) + strlen("cde-root") + 1);
                  strcpy(rel_path, "cde-root");
                  strcat(rel_path, filename);

                  struct path* p = str2path(rel_path);
                  path_pop(p); // ignore filename portion to leave just the dirname

                  // now mkdir all directories specified in rel_path
                  int i;
                  for (i = 1; i <= p->depth; i++) {
                    char* dn = path2str(p, i);
                    mkdir(dn, 0777);
                    free(dn);
                  }

                  // finally, 'copy' filename over to rel_path
                  // 1.) try a hard link for efficiency
                  // 2.) if that fails, then do a straight-up copy 
                  //     TODO: can optimize by first checking md5sum or
                  //     something before copying

                  // EEXIST means the file already exists, which isn't
                  // really a hard link failure ...
                  if (link(filename, rel_path) && (errno != EEXIST)) {
                    copy_file(filename, rel_path);
                  }

                  delete_path(p);
                  free(rel_path);
                }
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

