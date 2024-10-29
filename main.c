#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUFF_SIZE 1024
#define MAX_CHILDREN 4000

// struct for the cd command args
struct cd_struct {
  const char *target_directory;
  int error_code;
};

// struct for containing status info
struct status_info {
  int lastExitStatus;
  int lastTerminatingSignal;
  bool wasSignal;
};

// struct for keeping track and deleting child processes
struct child_manager {
  pid_t childPIDs[MAX_CHILDREN];
  int numChildren;
};

bool foregroundOnlyMode = false;

void remove_child_pid(struct child_manager *manager, pid_t pid) {
  for (int i = 0; i < manager->numChildren; i++) {
    if (manager->childPIDs[i] == pid) {

      // reset pid at the slot
      manager->childPIDs[i] = -1;

      // reduce num of children
      --manager->numChildren;

      break;
    }
  }
}

// function to monitor background processes
void monitor_background_process(struct child_manager *manager, int index) {
  int status;
  pid_t pid = manager->childPIDs[index];

  pid_t result = waitpid(pid, &status, WNOHANG);

  switch (result) {
  case 0:
    break;

  case -1:
    perror("waitpid failed");
    exit(1);
    break;

  default:
    if (WIFEXITED(status))
      printf("\nBackground pid %d is done: exit value %d\n", pid,
             WEXITSTATUS(status));

    else if (WIFSIGNALED(status))
      printf("\nBackground pid %d terminated by signal %d\n", pid,
             WTERMSIG(status));

    remove_child_pid(manager, pid);

    break;
  }
}

// helper function to find the redirection tokens
int find_redirection_index(char **args, char direction) {
  int i = 0;
  while (args[i] != NULL) {
    if ((direction == '<' && strcmp(args[i], "<") == 0) ||
        (direction == '>' && strcmp(args[i], ">") == 0)) {
      return i;
    }

    ++i;
  }
  return -1;
}

// helper function to add the child pids to an array
void addChildPID(struct child_manager *manager, pid_t pid) {
  if (manager->numChildren < MAX_CHILDREN)
    manager->childPIDs[manager->numChildren++] = pid;

  else
    fprintf(stderr, "Maximum number of child processes reached.\n");
}

// function to execute other UNIX commands
void execute_command(char **args, bool isBackground,
                     struct status_info *statusInfo,
                     struct child_manager *manager) {
  pid_t pid;

  int status;
  int in_fd;
  int out_fd;

  // ignore if comment
  if (args[0][0] == '#')
    return;

  // create new process
  pid = fork();

  switch (pid) {

  // fork failed
  case -1:
    perror("smallsh: fork failed");
    exit(1);
    break;

  // child process
  case 0: {

    // setup child to only have default behavior
    struct sigaction sa_default;
    sa_default.sa_handler = SIG_DFL;
    sigemptyset(&sa_default.sa_mask);
    sa_default.sa_flags = 0;
    sigaction(SIGINT, &sa_default, NULL);

    // handle foreground-only mode
    if (isBackground && foregroundOnlyMode)
      isBackground = false;

    int in_index = find_redirection_index(args, '<');

    if (in_index != -1) {
      in_fd = open(args[in_index + 1], O_RDONLY);

      if (in_fd == -1) {
        perror("Failed to open input file");
        exit(1);
      }

      dup2(in_fd, STDIN_FILENO);
      close(in_fd);

      // remove redirection argument
      while (args[in_index] != NULL) {
        args[in_index] = args[in_index + 2];
        in_index++;
      }
    }

    int out_index = find_redirection_index(args, '>');
    if (out_index != -1) {

      // open with write only with specific permissions
      out_fd = open(args[out_index + 1], O_WRONLY | O_CREAT | O_TRUNC, 0644);

      if (out_fd == -1) {
        perror("Failed to open output file");
        exit(1);
      }

      dup2(out_fd, STDOUT_FILENO);
      close(out_fd);

      // remove redirection argument
      while (args[out_index] != NULL) {
        args[out_index] = args[out_index + 2];
        out_index++;
      }
    }

    if (execvp(args[0], args) == -1) {
      perror("smallsh: command not found");
      exit(1);
    }

  } break;

  default:
    if (!isBackground) {
      // wait for the child process to complete
      while (waitpid(pid, &status, WUNTRACED) != pid) {

        if (errno == EINTR)
          continue;

        perror("smallsh: waitpid failed");
        exit(EXIT_FAILURE);
      }

      if (WIFSIGNALED(status))
        printf("Child process terminated by signal %d\n", WTERMSIG(status));

      if (WIFEXITED(status)) {
        // update structs with status if exited
        statusInfo->lastExitStatus = WEXITSTATUS(status);
        statusInfo->wasSignal = false;

      } else if (WIFSIGNALED(status)) {
        // update structs with status if exited by signal
        statusInfo->lastTerminatingSignal = WTERMSIG(status);
        statusInfo->wasSignal = true;
      }

    } else {

      // add the child pid to array
      addChildPID(manager, pid);

      // print pid of background
      printf("Background PID is %d\n", pid);
      fflush(stdout);
    }

    break;
  }
}

// beginning of handling input  ---------------------------------------

// function to read the raw input from user
ssize_t read_input(char **input, size_t *size) {
  fflush(stdout);
  printf(": ");
  fflush(stdout);
  ssize_t chars_read = getline(input, size, stdin);
  fflush(stdin);

  if (chars_read > 0) {
    size_t last_char_index = chars_read - 1;

    if ((*input)[last_char_index] == '\n') {

      // replace the newline character with a null terminator
      (*input)[last_char_index] = '\0';
    }
  }

  return chars_read;
}

int parse_input(char *input, char **args, int max_args) {
  int argc = 0;
  char *token;
  char *saveptr;

  token = strtok_r(input, " ", &saveptr);
  while (token != NULL && argc < max_args - 1) {
    args[argc++] = token;
    token = strtok_r(NULL, " ", &saveptr);
  }

  args[argc] = NULL;

  return argc;
}

bool handle_background_flag(char **args, int *argc) {
  if (*argc > 0 && strcmp(args[*argc - 1], "&") == 0) {
    --(*argc);
    args[*argc] = NULL;
    return true;
  }

  return false;
}

// function to replace dollar sign with shell PID
void emplace_dollar_sign(char *input) {
  pid_t pid = getpid();
  char pidString[32];
  sprintf(pidString, "%d", pid);

  // get more memory than usual
  char *result = malloc(strlen(input) + 1 + strlen(pidString) * 10);

  char *src = input;

  char *dst = result;

  while (*src) {
    if (src[0] == '$' && src[1] == '$') {
      strcpy(dst, pidString);
      dst += strlen(pidString);

      // skip two
      src += 2;
    } else
      // copy normal characters
      *dst++ = *src++;
  }

  *dst = '\0';
  strcpy(input, result);
  free(result);
}

// end of handling input  ---------------------------------------

// function to handle the cd  command
void handle_cd(struct cd_struct *c) {
  if (c->target_directory == NULL || strcmp(c->target_directory, "~") == 0) {
    c->target_directory = getenv("HOME");

    if (c->target_directory == NULL) {
      fprintf(stderr, "smallsh: cd: HOME not set\n");
      c->error_code = 1;
      return;
    }
  }

  if (chdir(c->target_directory) != 0) {
    perror("smallsh: cd");
    c->error_code = 1;
  } else
    c->error_code = 0;
}

// function to handle the exit command
void handle_exit(struct child_manager *manager) {
  for (int i = 0; i < manager->numChildren; i++) {
    if (manager->childPIDs[i] != -1) {
      // kill all active processes
      kill(manager->childPIDs[i], SIGTERM);

      // wait until its killed
      waitpid(manager->childPIDs[i], NULL, 0);
    }
  }

  exit(0);
}

// function to handle the status command
void handle_status(const struct status_info statusInfo) {
  if (!statusInfo.wasSignal)
    printf("exit value %d\n", statusInfo.lastExitStatus);
  else
    printf("terminated by signal %d\n", statusInfo.lastTerminatingSignal);
}

// function to handle behavior when ctrl + z is pressed via signals
void handle_SIGTSTP(int signum) {
  foregroundOnlyMode = !foregroundOnlyMode;

  if (foregroundOnlyMode) {
    const char *message =
        "\nEntering foreground-only mode (& is now ignored)\n";
    write(STDOUT_FILENO, message, strlen(message));

    fflush(stdout);
  } else {
    const char *message = "\nExiting foreground-only mode\n";
    write(STDOUT_FILENO, message, strlen(message));
    fflush(stdout);
  }
}

// setup signals within main
void setup(struct child_manager *manager) {

  // set up signal to ignore ctrl + c
  struct sigaction sa_ignore;
  sa_ignore.sa_handler = SIG_IGN;
  sigemptyset(&sa_ignore.sa_mask);
  sa_ignore.sa_flags = 0;
  sigaction(SIGINT, &sa_ignore, NULL);

  // setup signal to handle ctrl + z
  struct sigaction sa_SIGTSTP;
  memset(&sa_SIGTSTP, 0, sizeof(sa_SIGTSTP));
  sa_SIGTSTP.sa_handler = handle_SIGTSTP;
  sigfillset(&sa_SIGTSTP.sa_mask);
  sa_SIGTSTP.sa_flags = SA_RESTART;
  sigaction(SIGTSTP, &sa_SIGTSTP, NULL);

  // initialize all the entries to be -1
  for (int i = 0; i < MAX_CHILDREN; ++i)
    manager->childPIDs[i] = -1;

  manager->numChildren = 0;
}

int main() {
  char *input = NULL;
  size_t size = 0;
  ssize_t chars_read;

  struct status_info statusInfo = {0, 0, false};
  struct child_manager manager;

  // setup child_manager array
  setup(&manager);

  for (;;) {

    // monitor each background process
    for (int i = 0; i < manager.numChildren; i++) {
      if (manager.childPIDs[i] != -1)
        monitor_background_process(&manager, i);
    }

    chars_read = read_input(&input, &size);

    // input error
    if (chars_read == -1)
      break;

    emplace_dollar_sign(input);

    char *args[BUFF_SIZE];
    int argc = parse_input(input, args, BUFF_SIZE);

    // if no args just continue
    if (argc == 0)
      continue;

    // check if there is a background flag
    bool background = handle_background_flag(args, &argc);

    // handle built-in and non built in commands
    if (strcmp(args[0], "exit") == 0)
      handle_exit(&manager);

    else if (strcmp(args[0], "cd") == 0) {
      struct cd_struct c;
      c.target_directory = args[1];
      c.error_code = 0;
      handle_cd(&c);

    } else if (strcmp(args[0], "status") == 0)
      handle_status(statusInfo);

    else
      // non built-in commands
      execute_command(args, background, &statusInfo, &manager);
  }

  free(input);

  return 0;
}
