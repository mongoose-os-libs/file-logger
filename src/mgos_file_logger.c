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

static bool s_disable = false;
static FILE *s_curfile = NULL;
static char *s_curfile_name = NULL;
static bool s_rotate = false;
static bool s_log_wall_time = false;
static uint8_t s_set = 0;
static uint8_t s_seq = 0;

// Old name format: log_20200124-002925.706.txt
static bool is_old_name(const char *name, size_t prefix_len) {
  return (name != NULL && name[prefix_len + 3] != '-');
}

static bool get_file_seq(const char *name, uint8_t *set, uint8_t *seq) {
  size_t prefix_len = strlen(mgos_sys_config_get_file_logger_prefix());
  if (name[prefix_len + 3] != '-') return false;
  const char *p = name + prefix_len;
  *set = (p[0] - '0');
  *seq = ((p[1] - '0') * 10 + (p[2] - '0'));
  return true;
}

/*
 * Allocates and returns new filename for the log; caller needs to free it.
 */
static char *get_new_log_filename(void) {
  struct mg_str logsdir = mg_mk_str(mgos_sys_config_get_file_logger_dir());
  char *ret = NULL;
  int max_seq = mgos_sys_config_get_file_logger_max_num_files() - 1;

  if (s_seq < 100) {
    s_seq++;
  } else {
    s_seq = 0;
    s_set++;
    if (s_set > 2 || max_seq == 0) s_set = 0;
  }

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
  mg_asprintf(&ret, 0, "%.*s/%s%d%.2d-%.4d%.2d%.2d-%.2d%.2d%.2d.log",
              (int) logsdir.len, logsdir.p,
              mgos_sys_config_get_file_logger_prefix(), s_set, s_seq,
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

struct set_info {
  char *oldest;
  char *newest;
};

/*
 * Writes filenames of the oldest and/or newest log files to the provided
 * pointers. Pointers can be NULL.
 *
 * Returns total number of log files found.
 */
static int get_oldest_newest(char **oldest, uint8_t *oldest_set,
                             uint8_t *oldest_seq, char **newest,
                             uint8_t *newest_set, uint8_t *newest_seq) {
  /*
   * To ensure correct and efficient handling of rollover,
   * files are organized into 3 sets, numbered from 0 to 2.
   * Each set can have up to 100 files, numbered from 0 to 99.
   * Sets roll over from 0 to 1 to 2 and back to 0.
   * For efficiency reasons, we only make one pass over the directory.
   * We can encounter files from at most two sets at the same time:
   * 0 only, 0 and 1, 1 only, 1 and 2, 2 only, 2 and 0.
   * We keep track of maximum and minimum element in the three sets separately
   * and at the end, based on which sets were seen,
   * decide from which set to pick.
   */
  int cnt = 0;
  struct set_info sets[3] = {{0}, {0}, {0}};
  char **po = NULL, **pn = NULL;

  if (oldest != NULL) {
    *oldest = NULL;
  }
  if (newest != NULL) {
    *newest = NULL;
  }

  DIR *dirp = opendir(mgos_sys_config_get_file_logger_dir());
  if (dirp == NULL) {
    return 0;
  }

  struct dirent *dp;
  const char *prefix = mgos_sys_config_get_file_logger_prefix();
  size_t prefix_len = strlen(prefix);
  uint8_t mask = 0;
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

    uint8_t set = 0, seq = 0;
    if (!get_file_seq(name, &set, &seq) || set > 2) {
      // Weird stuff (including old names) gots into set 0.
      set = 0;
    }
    mask |= (1 << set);
    po = &sets[set].oldest;
    pn = &sets[set].newest;
    bool is_older = false, is_newer = false;
    if (!is_old_name(name, prefix_len)) {
      if (po != NULL) {
        if (*po == NULL) {
          is_older = true;
        } else if (is_old_name(*po, prefix_len)) {
          is_older = false;  // New name is never older than old.
        } else {
          is_older = (strcmp(name, *po) < 0);
        }
      }
      if (pn != NULL) {
        is_newer = (*pn == NULL || strcmp(name, *pn) > 0);
      }
    } else {
      if (po != NULL) {
        if (*po == NULL) {
          is_older = true;
        } else if (is_old_name(*po, prefix_len)) {
          is_older = (strcmp(name, *po) < 0);
        } else {
          is_older = true;
        }
      }
      // Never pick file with old name as newest, better create a new one.
      is_newer = false;
    }
    if (is_older) {
      free(*po);
      *po = strdup(name);
    }
    if (is_newer) {
      free(*pn);
      *pn = strdup(name);
    }
  }

  closedir(dirp);

  // Determine which set to use for oldest and newest.
  switch (mask) {
    default:  // everything else -> set 0.
              // fall through
    case 1:   // 001
      po = &sets[0].oldest;
      pn = &sets[0].newest;
      break;
    case 3:  // 011
      po = &sets[0].oldest;
      pn = &sets[1].newest;
      break;
    case 2:  // 010
      po = &sets[1].oldest;
      pn = &sets[1].newest;
      break;
    case 6:  // 110
      po = &sets[1].oldest;
      pn = &sets[2].newest;
      break;
    case 4:  // 100
      po = &sets[2].oldest;
      pn = &sets[2].newest;
      break;
    case 5:  // 101
      po = &sets[2].oldest;
      pn = &sets[0].newest;
      break;
  }

  // Copy out the results, adding directory.
  // Avoiding (a)sprintf to reduce stack usage.
  size_t dir_len = strlen(mgos_sys_config_get_file_logger_dir());
  if (oldest != NULL && *po != NULL) {
    char *tmp = *po;
    size_t tmp_len = strlen(tmp);
    *po = NULL;
    get_file_seq(tmp, oldest_set, oldest_seq);
    *oldest = calloc(1, dir_len + 1 + tmp_len + 1);
    if (*oldest != NULL) {
      memcpy(*oldest, mgos_sys_config_get_file_logger_dir(), dir_len);
      (*oldest)[dir_len] = '/';
      memcpy((*oldest) + dir_len + 1, tmp, tmp_len);
    }
    free(tmp);
  }

  if (newest != NULL && *pn != NULL) {
    char *tmp = *pn;
    size_t tmp_len = strlen(tmp);
    *pn = NULL;
    get_file_seq(tmp, newest_set, newest_seq);
    *newest = calloc(1, dir_len + 1 + tmp_len + 1);
    if (*newest != NULL) {
      memcpy(*newest, mgos_sys_config_get_file_logger_dir(), dir_len);
      (*newest)[dir_len] = '/';
      memcpy((*newest) + dir_len + 1, tmp, tmp_len);
    }
    free(tmp);
  }

  // Free unused strings.
  for (int i = 0; i < 3; i++) {
    free(sets[i].oldest);
    free(sets[i].newest);
  }

  return cnt;
}

static bool init_file(size_t msg_len) {
  bool res = false;
  int num_files = -1,
      max_files = mgos_sys_config_get_file_logger_max_num_files();
  char *oldest = NULL, *newest = NULL;
  uint8_t oldest_set = 0, oldest_seq = 0;
  uint8_t newest_set = 0, newest_seq = 0;

  // No file open? Open latest, if any.
  if (s_curfile == NULL) {
    num_files = get_oldest_newest(&oldest, &oldest_set, &oldest_seq, &newest,
                                  &newest_set, &newest_seq);
    if (newest != NULL && !s_rotate) {
      s_set = newest_set;
      s_seq = newest_seq;
      s_curfile = fopen(newest, "a");
      if (s_curfile != NULL) {
        set_file_buf(s_curfile);
        long size = ftell(s_curfile);
        LOG(LL_DEBUG,
            ("Opened %s (seq %d/%d, size %ld)", newest, s_set, s_seq, size));
        if (size <= 0) {
          /* It's a trap! File cannot be zero size, likely FS corruption.
           * Try to re-create. */
          LOG(LL_INFO, ("Found truncated file %s, re-creating", newest));
          fclose(s_curfile);
          remove(newest);
          s_curfile = NULL;
        } else {
          s_curfile_name = newest;
          newest = NULL;
        }
      }
    } else if (newest != NULL) {
      s_set = newest_set;
      s_seq = newest_seq;
    } else {
      // Start at 0.
      s_set = 2;
      s_seq = (uint8_t) -1;
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

  // Check file count, we may need to clean up extra file(s).
  if (num_files < 0) {
    num_files =
        get_oldest_newest(&oldest, &oldest_set, &oldest_seq, NULL, NULL, NULL);
  }
  while (num_files >= max_files) {
    if (remove(oldest) == 0) {
      LOG(LL_DEBUG, ("Removed %s", oldest));
    }
    free(oldest);
    oldest = NULL;
    num_files--;
    if (num_files < mgos_sys_config_get_file_logger_max_num_files()) break;
    num_files =
        get_oldest_newest(&oldest, &oldest_set, &oldest_seq, NULL, NULL, NULL);
  }

  // Could not open an existing file? Create a new one.
  if (s_curfile == NULL) {
    s_curfile_name = get_new_log_filename();
    s_curfile = fopen(s_curfile_name, "w");
    if (s_curfile != NULL) {
      LOG(LL_DEBUG, ("Created %s (seq %d/%d)", s_curfile_name, s_set, s_seq));
      set_file_buf(s_curfile);
      res = true;
    } else {
      free(s_curfile_name);
      s_curfile_name = NULL;
    }
  }

out:
  free(oldest);
  free(newest);
  return res;
}

static bool should_log(enum cs_log_level level, struct mg_str msg) {
  if (!mgos_sys_config_get_file_logger_enable() || s_disable) return false;
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
  free(s_curfile_name);
  s_curfile_name = NULL;
}

void mgos_file_log_rotate(void) {
  if (s_curfile == NULL) return;
  mgos_file_log_flush();
  s_rotate = true;
}

char *mgos_file_log_get_cur_file_name(void) {
  if (s_curfile_name == NULL) return NULL;
  return strdup(s_curfile_name);
}

static void reboot_cb(int ev, void *ev_data, void *userdata) {
  mgos_file_log_flush();
  s_disable = true;
  (void) ev;
  (void) ev_data;
  (void) userdata;
}

#ifdef MGOS_HAVE_RPC_COMMON
static void file_log_status_handler(struct mg_rpc_request_info *ri,
                                    void *cb_arg, struct mg_rpc_frame_info *fi,
                                    struct mg_str args) {
  char *oldest = NULL, *newest = NULL;
  uint8_t oldest_set = 0, oldest_seq = 0;
  uint8_t newest_set = 0, newest_seq = 0;
  int num_files = get_oldest_newest(&oldest, &oldest_set, &oldest_seq, &newest,
                                    &newest_set, &newest_seq);
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
  if (mgos_sys_config_get_file_logger_max_num_files() > 100) {
    return false;
  }

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
