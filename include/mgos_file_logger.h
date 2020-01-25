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

#pragma once

#include <stdbool.h>

#include "common/cs_dbg.h"
#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

bool mgos_file_log(enum cs_log_level level, struct mg_str msg);

bool mgos_file_logf(enum cs_log_level level, const char *fmt, ...);

void mgos_file_log_flush(void);

void mgos_file_log_rotate(void);

#ifdef __cplusplus
}
#endif
