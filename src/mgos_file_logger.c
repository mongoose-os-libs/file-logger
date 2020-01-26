/*
 * Copyright (c) 2020 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_file_logger.h"

#include "mgos.h"
#ifdef MGOS_HAVE_RPC_COMMON
#include "mgos_rpc.h"
#endif

static bool s_rotate = false;
static bool s_log_wall_time = false;
static unsigned int s_seq = 0;
static FILE *s_curfile = NULL;

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
static int get_oldest_newest(char **poldest, int *oldest_seq, char **pnewest,
                             int *newest_seq) {
  int cnt = 0;

  if (poldest != NULL) {
    *poldest = NULL;
    *oldest_seq = 0;
  }
  if (pnewest != NULL) {
    *pnewest = NULL;
    *newest_seq = 0;
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

  if (poldest != NULL && *poldest != NULL) {
    char *tmp = *poldest;
    *poldest = NULL;
    *oldest_seq = get_file_seq(tmp);
    mg_asprintf(poldest, 0, "%s/%s", mgos_sys_config_get_file_logger_dir(),
                tmp);
    free(tmp);
  }

  if (pnewest != NULL && *pnewest != NULL) {
    char *tmp = *pnewest;
    *pnewest = NULL;
    *newest_seq = get_file_seq(tmp);
    mg_asprintf(pnewest, 0, "%s/%s", mgos_sys_config_get_file_logger_dir(),
                tmp);
    free(tmp);
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
  mg_asprintf(&ret, 0, "%.*s/%s%.3d-%.4d%.2d%.2d-%.2d%.2d%.2d.log",
              (int) logsdir.len, logsdir.p,
              mgos_sys_config_get_file_logger_prefix(), s_seq,
              tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
              tm.tm_min, tm.tm_sec);
  return ret;
}

static void set_file_buf(FILE *fp) {
  if (fp == NULL) return;
  if (mgos_sys_config_get_file_logger_buf_size() < 0) return;
  setvbuf(fp, NULL,
          (mgos_sys_config_get_file_logger_buf_line() ? _IOLBF : _IOFBF),
          mgos_sys_config_get_file_logger_buf_size());
}

static bool init_file(size_t msg_len) {
  bool res = false;
  int num_files = -1;
  char *curfilename = NULL;
  char *oldest = NULL, *newest = NULL;
  int oldest_seq = 0, newest_seq = 0;

  // No file open? Open latest, if any.
  if (s_curfile == NULL) {
    num_files = get_oldest_newest(&oldest, &oldest_seq, &newest, &newest_seq);
    if (num_files > 0 && !s_rotate && newest != NULL) {
      s_seq = newest_seq;
      s_curfile = fopen(newest, "a");
      if (s_curfile != NULL) {
        set_file_buf(s_curfile);
        long size = ftell(s_curfile);
        LOG(LL_DEBUG, ("Opened %s (seq %d, size %ld)", newest, s_seq, size));
        if (size <= 0) {
          /* It's a trap! FIle cannot be zero size, likely FS corruption.
           * Try to re-create. */
          LOG(LL_INFO, ("Found truncated file %s, re-creating", newest));
          fclose(s_curfile);
          remove(newest);
          s_curfile = NULL;
        }
      }
    } else if (num_files > 0 && s_rotate) {
      s_seq = newest_seq;
    }
    s_rotate = false;
  }

  // Have an open file? Check if it's time to rotate.
  if (s_curfile != NULL) {
    if (ftell(s_curfile) + (long) msg_len >
        mgos_sys_config_get_file_logger_max_file_size()) {
      fclose(s_curfile);
      s_curfile = NULL;
    } else {
      res = true;
      goto out;
    }
  }

  // Need to open a new file. Check file count first, make room if needed.
  if (num_files < 0) {
    num_files = get_oldest_newest(&oldest, &oldest_seq, NULL, NULL);
  }
  while (num_files >= mgos_sys_config_get_file_logger_max_num_files()) {
    LOG(LL_DEBUG, ("Removing %s", oldest));
    remove(oldest);
    free(oldest);
    oldest = NULL;
    num_files--;
    if (num_files < mgos_sys_config_get_file_logger_max_num_files()) break;
    num_files = get_oldest_newest(&oldest, &oldest_seq, NULL, NULL);
  }

  curfilename = get_new_log_filename();
  s_curfile = fopen(curfilename, "w");
  if (s_curfile != NULL) {
    LOG(LL_DEBUG, ("Created %s (seq %d)", curfilename, s_seq));
    set_file_buf(s_curfile);
    res = true;
  }

out:
  free(curfilename);
  free(oldest);
  free(newest);
  return res;
}

static bool should_log(enum cs_log_level level, struct mg_str msg) {
  if (!mgos_sys_config_get_file_logger_enable()) return false;
  if (level > mgos_sys_config_get_file_logger_level()) return false;
  bool res = true;
  struct mg_str inc = mg_mk_str(mgos_sys_config_get_file_logger_include());
  if (inc.len > 0) {
    res = false;
    struct mg_str k, v;
    while ((inc = mg_next_comma_list_entry_n(inc, &k, &v)).p != NULL) {
      res = (mg_strstr(msg, k) != NULL);
      if (res) break;
    }
  }
  return res;
}

static bool write_header(void) {
  if (mgos_sys_config_get_file_logger_timestamps()) {
    if (s_log_wall_time) {
      fprintf(s_curfile, "%lld:%lld ", (long long) mgos_uptime_micros(),
              (long long) mgos_time_micros());
      s_log_wall_time = false;
    } else {
      fprintf(s_curfile, "%lld ", (long long) mgos_uptime_micros());
    }
  }
  return true;
}

bool mgos_file_log(enum cs_log_level level, struct mg_str msg) {
  if (msg.len == 0 || !should_log(level, msg)) return false;
  if (!init_file(msg.len)) return false;
  if (!write_header()) return false;
  bool res = (fwrite(msg.p, 1, msg.len, s_curfile) == msg.len);
  if (res && msg.p[msg.len - 1] != '\n') {
    fwrite("\n", 1, 1, s_curfile);
  }
  return res;
}

bool mgos_file_logf(enum cs_log_level level, const char *fmt, ...) {
  if (fmt == NULL || level > mgos_sys_config_get_file_logger_level()) {
    return false;
  }
  char *msg = NULL;
  va_list ap;
  va_start(ap, fmt);
  mg_avprintf(&msg, 0, fmt, ap);
  bool res = mgos_file_log(level, mg_mk_str(msg));
  va_end(ap);
  free(msg);
  return res;
}

static void debug_write_cb(int ev, void *ev_data, void *userdata) {
  static bool s_cont = false;
  const struct mgos_debug_hook_arg *arg = ev_data;
  struct mg_str msg = MG_MK_STR_N(arg->data, arg->len);
  // Is this a continuation of a previous line?
  // (messages can be split over several invocations).
  // Continuations are always logged.
  if (msg.len == 0 || (!s_cont && !should_log(arg->level, msg))) return;
  if (!init_file(msg.len)) return;
  if (!s_cont && !write_header()) return;
  fwrite(msg.p, 1, msg.len, s_curfile);
  s_cont = (msg.p[msg.len - 1] != '\n');
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

void mgos_file_log_flush(void) {
  if (s_curfile == NULL) return;
  fclose(s_curfile);
  s_curfile = NULL;
}

void mgos_file_log_rotate(void) {
  if (s_curfile == NULL) return;
  mgos_file_log_flush();
  s_rotate = true;
}

static void reboot_cb(int ev, void *ev_data, void *userdata) {
  mgos_file_log_flush();
  (void) ev;
  (void) ev_data;
  (void) userdata;
}

#ifdef MGOS_HAVE_RPC_COMMON
static void file_log_status_handler(struct mg_rpc_request_info *ri,
                                    void *cb_arg, struct mg_rpc_frame_info *fi,
                                    struct mg_str args) {
  char *oldest = NULL, *newest = NULL;
  int oldest_seq = 0, newest_seq = 0;
  int num_files = get_oldest_newest(&oldest, &oldest_seq, &newest, &newest_seq);
  mg_rpc_send_responsef(ri,
                        "{enable: %B, num_files: %d, oldest: %Q, newest: %Q}",
                        mgos_sys_config_get_file_logger_enable(), num_files,
                        (oldest ? oldest : ""), (newest ? newest : ""));
  (void) fi;
  (void) args;
  (void) cb_arg;
}

static void file_log_flush_rotate_handler(struct mg_rpc_request_info *ri,
                                          void *cb_arg,
                                          struct mg_rpc_frame_info *fi,
                                          struct mg_str args) {
  if (cb_arg == NULL) {
    mgos_file_log_flush();
  } else {
    mgos_file_log_rotate();
  }
  mg_rpc_send_responsef(ri, NULL);
  (void) fi;
  (void) args;
}
#endif

bool mgos_file_logger_init(void) {
  if (mgos_sys_config_get_file_logger_timestamps()) {
    if (mgos_time_micros() > 0x4000000000000) {
      // Wall time is set, log it with the first message.
      s_log_wall_time = true;
    }
    mgos_event_add_handler(MGOS_EVENT_TIME_CHANGED, time_changed_cb, NULL);
  }

  mgos_event_add_handler(MGOS_EVENT_REBOOT, reboot_cb, NULL);

  if (mgos_sys_config_get_file_logger_syslog_enable()) {
    mgos_event_add_handler(MGOS_EVENT_LOG, debug_write_cb, NULL);
  }

#ifdef MGOS_HAVE_RPC_COMMON
  if (mgos_sys_config_get_file_logger_rpc_service_enable()) {
    struct mg_rpc *c = mgos_rpc_get_global();
    mg_rpc_add_handler(c, "FileLog.Status", "", file_log_status_handler, NULL);
    mg_rpc_add_handler(c, "FileLog.Flush", "", file_log_flush_rotate_handler,
                       NULL);
    mg_rpc_add_handler(c, "FileLog.Rotate", "", file_log_flush_rotate_handler,
                       (void *) 1);
  }
#endif

  return true;
}
