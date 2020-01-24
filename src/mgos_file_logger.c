#include <stdbool.h>

#include "mgos.h"
#include "mgos_uart.h"

static bool s_log_wall_time = false;
static unsigned int s_seq = 0;
static FILE *s_curfile = NULL;
static char *s_curfilename = NULL;

// Old name format: log_20200124-002925.706.txt
static bool is_old_name(const char *name, size_t prefix_len) {
  return (name != NULL && name[prefix_len + 3] != '-');
}

static unsigned int get_file_seq(const char *name) {
  size_t prefix_len = strlen(mgos_sys_config_get_file_logger_prefix());
  if (name[prefix_len + 3] != '-') return 0;
  return (((name[prefix_len] - '0') * 100) +
          ((name[prefix_len + 1] - '0') * 10) + (name[prefix_len + 2] - '0'));
}

/*
 * Writes filenames of the oldest and/or newest log files to the provided
 * pointers. Pointers can be NULL.
 *
 * Returns total number of log files found.
 */
static int get_oldest_newest(char **poldest, char **pnewest) {
  int cnt = 0;

  if (poldest != NULL) {
    *poldest = NULL;
  }
  if (pnewest != NULL) {
    *pnewest = NULL;
  }

  DIR *dirp = opendir(mgos_sys_config_get_file_logger_dir());
  if (dirp == NULL) {
    return 0;
  }

  struct dirent *dp;
  const char *prefix = mgos_sys_config_get_file_logger_prefix();
  size_t prefix_len = strlen(prefix);
  while ((dp = readdir(dirp)) != NULL) {
    const char *name = dp->d_name;
    if (strncmp(name, prefix, prefix_len) != 0) {
      continue;
    }
    /* One of the log files */
    cnt++;

    /*
     * We rely on file names to be lexicographically sortable.
     * Files with old naming scheme are not directly comparable,
     * so we need to play tricks.
     */

    bool is_older = false, is_newer = false;
    if (!is_old_name(name, prefix_len)) {
      if (poldest != NULL) {
        if (*poldest == NULL) {
          is_older = true;
        } else if (is_old_name(*poldest, prefix_len)) {
          is_older = false;  // New name is never older than old.
        } else {
          is_older = (strcmp(name, *poldest) < 0);
        }
      }
      if (pnewest != NULL) {
        is_newer = (*pnewest == NULL || strcmp(name, *pnewest) > 0);
      }
    } else {
      if (poldest != NULL) {
        if (*poldest == NULL) {
          is_older = true;
        } else if (is_old_name(*poldest, prefix_len)) {
          is_older = (strcmp(name, *poldest) < 0);
        } else {
          is_older = true;
        }
      }
      /* Never pick file with old name as newest, better create a new one. */
      is_newer = false;
    }
    if (is_older) {
      free(*poldest);
      *poldest = strdup(name);
    }
    if (is_newer) {
      free(*pnewest);
      *pnewest = strdup(name);
    }
  }

  closedir(dirp);

  return cnt;
}

/*
 * Allocates and returns new filename for the log; caller needs to free it.
 */
static char *get_new_log_filename(void) {
  struct mg_str logsdir = mg_mk_str(mgos_sys_config_get_file_logger_dir());
  char *ret = NULL;

  s_seq++;
  if (s_seq >= 1000) s_seq = 0;

  if (logsdir.len > 0 && logsdir.p[logsdir.len - 1] == '/') {
    logsdir.len--;
  }

  double td = mg_time();
  time_t t = (time_t) td;
  struct tm tm;
#ifdef _REENT
  localtime_r(&t, &tm);
#else
  memcpy(&tm, localtime(&t), sizeof(tm));
#endif
  mg_asprintf(&ret, 0, "%.*s/%s%.3d-%.4d%.2d%.2d-%.2d%.2d%.2d.txt",
              (int) logsdir.len, logsdir.p,
              mgos_sys_config_get_file_logger_prefix(), s_seq,
              tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
              tm.tm_min, tm.tm_sec);
  return ret;
}

static void init_curfile(void) {
  if (s_curfile != NULL) {
    fclose(s_curfile);
    s_curfile = NULL;
  }
  if (s_curfilename == NULL) {
    return;
  }
  s_curfile = fopen(s_curfilename, "a");
  if (s_curfile == NULL) {
    LOG(LL_ERROR, ("failed to open log file '%s'", s_curfilename));
    return;
  }
  setvbuf(s_curfile, NULL, _IOLBF, 256);
}

static void debug_write_cb(int ev, void *ev_data, void *userdata) {
  const struct mgos_debug_hook_arg *arg = ev_data;
  // Is this a continuation of a previous line?
  // (messages can be split over several invocations).
  static bool s_cont = false;

  if (s_curfile == NULL) return;

  /* Does this message need to be logged? */
  if (!s_cont) {  // We always log continuations of previous messages.
    if (arg->level > mgos_sys_config_get_file_logger_level()) return;
    struct mg_str inc = mg_mk_str(mgos_sys_config_get_file_logger_include());
    if (inc.len > 0) {
      struct mg_str k, v, msg = MG_MK_STR_N(arg->data, arg->len);
      bool include = false;
      while ((inc = mg_next_comma_list_entry_n(inc, &k, &v)).p != NULL) {
        include = (mg_strstr(msg, k) != NULL);
        if (include) break;
      }
      if (!include) return;
    }
  }

  /* Before writing to the current log file, check if it's too large already */
  if (ftell(s_curfile) + (long) arg->len >
      mgos_sys_config_get_file_logger_max_file_size()) {
    /* Check if there are too many files already */
    char *oldest = NULL;
    int log_files_cnt;
    do {
      log_files_cnt = get_oldest_newest(&oldest, NULL);

      if (log_files_cnt >= mgos_sys_config_get_file_logger_max_num_files()) {
        /* Yes, there are too many; delete the found oldest one */
        remove(oldest);
        log_files_cnt--;
      }

      free(oldest);
      oldest = NULL;
    } while (log_files_cnt >= mgos_sys_config_get_file_logger_max_num_files());

    free(s_curfilename);
    s_curfilename = get_new_log_filename();
    init_curfile();
    if (s_curfile == NULL) return;
  }

  /* Finally, write piece of data to the current log file */
  if (s_curfile != NULL) {
    if (mgos_sys_config_get_file_logger_timestamps() && !s_cont) {
      if (s_log_wall_time) {
        fprintf(s_curfile, "%lld:%lld %.*s", (long long) mgos_uptime_micros(),
                (long long) mgos_time_micros(), (int) arg->len, arg->data);
        s_log_wall_time = false;
      } else {
        fprintf(s_curfile, "%lld %.*s", (long long) mgos_uptime_micros(),
                (int) arg->len, arg->data);
      }
    } else {
      fwrite(arg->data, arg->len, 1, s_curfile);
    }
    s_cont = (arg->data[arg->len - 1] != '\n');
  }

  (void) ev;
  (void) userdata;
}

static void time_changed_cb(int ev, void *ev_data, void *userdata) {
  // Log updated wall time with the next message.
  s_log_wall_time = true;
  (void) ev;
  (void) ev_data;
  (void) userdata;
}

static void reboot_cb(int ev, void *ev_data, void *userdata) {
  if (s_curfile == NULL) return;
  fclose(s_curfile);
  s_curfile = NULL;
  (void) ev;
  (void) ev_data;
  (void) userdata;
}

bool mgos_file_logger_init(void) {
  if (!mgos_sys_config_get_file_logger_enable()) return true;

  /* Get the newest filename (if any) */
  get_oldest_newest(NULL, &s_curfilename);

  if (s_curfilename == NULL) {
    /* No log files are found, generate a new one */
    s_curfilename = get_new_log_filename();
  } else {
    s_seq = get_file_seq(s_curfilename);
  }
  if (s_curfilename != NULL) {
    LOG(LL_INFO, ("Current file: %s (seq %d)", s_curfilename, s_seq));
  }

  init_curfile();

  if (mgos_sys_config_get_file_logger_timestamps()) {
    if (mgos_time_micros() > 0x4000000000000) {
      // Wall time is set, log it with the first message.
      s_log_wall_time = true;
    }
    mgos_event_add_handler(MGOS_EVENT_TIME_CHANGED, time_changed_cb, NULL);
  }

  mgos_event_add_handler(MGOS_EVENT_LOG, debug_write_cb, NULL);
  mgos_event_add_handler(MGOS_EVENT_REBOOT, reboot_cb, NULL);

  return true;
}
