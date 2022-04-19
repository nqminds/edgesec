#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "utils/log.h"

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void lock_fn(bool lock) {
  int res;

  if (lock) {
    res = pthread_mutex_lock(&mtx);
    if (res != 0) {
      perror("pthread_mutex_lock\n");
      exit(1);
    }
  } else {
    res = pthread_mutex_unlock(&mtx);
    if (res != 0) {
      perror("pthread_mutex_unlock\n");
      exit(1);
    }
  }
}

static void *threadFunc(void *arg) {
  for (int i = 0; i < 1000; i++)
    log_trace((char *)arg);
  return NULL;
}

int main(int argc, char *argv[]) {
  char *thread_one_text = "one";
  char *thread_two_text = "two";

  log_set_meta(0);
  log_set_lock(lock_fn);

  int fd;
  char tmp_file[] = "/tmp/test_log_threadXXXXXX";
  fd = mkstemp(tmp_file);
  if (fd == -1) {
    perror("mkstemp");
    exit(1);
  }

  int save_err = dup(fileno(stderr));
  if (-1 == dup2(fd, fileno(stderr))) {
    perror("dup2");
    exit(1);
  }

  pthread_t test_thread_one, test_thread_two;
  int thread_output_one, thread_output_two;

  thread_output_one = pthread_create(&test_thread_one, NULL, threadFunc,
                                     (char *)thread_one_text);

  if (thread_output_one != 0) {
    perror("pthread_create one error\n");
    exit(1);
  }

  thread_output_two = pthread_create(&test_thread_two, NULL, threadFunc,
                                     (char *)thread_two_text);

  if (thread_output_two != 0) {
    perror("pthread_create two error\n");
    exit(1);
  }

  thread_output_one = pthread_join(test_thread_one, NULL);
  if (thread_output_one != 0) {
    perror("pthread_join one error\n");
    exit(1);
  }

  thread_output_two = pthread_join(test_thread_two, NULL);
  if (thread_output_two != 0) {
    perror("pthread_join two error\n");
    exit(1);
  }

  fflush(stderr);
  close(fd);
  dup2(save_err, fileno(stderr));
  close(save_err);

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  FILE *fp = fopen(tmp_file, "r");

  if (fp == NULL) {
    perror("fopen error\n");
    exit(1);
  }

  while ((read = getline(&line, &len, fp)) != -1) {
    int8_t result_one = strcmp(line, "one\n");
    int8_t result_two = strcmp(line, "two\n");
    if (result_one != 0 && result_two != 0) {
      perror("Race condition detected error\n");
      if (line)
        free(line);
      unlink(tmp_file);
      fclose(fp);
      exit(1);
    }
  }

  if (line)
    free(line);
  unlink(tmp_file);
  fclose(fp);

  exit(0);
}
