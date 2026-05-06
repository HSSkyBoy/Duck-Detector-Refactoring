/*
 * Copyright 2026 Duck Apps Contributor
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

#include "nativeroot/probes/devpts_abnormal_permission_probe.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <cstdlib>

namespace duckdetector::nativeroot {

    void check_and_fill_finding(const char* path, ProbeResult& result) {
        struct stat st{};
        if (lstat(path, &st) == -1) {
            return;
        }

        result.checked_count++;
        char attr_val[256] = {0};
        bool is_abnormal = false;

        Finding finding;
        finding.group = "devpts_permission";
        finding.label = path;
        finding.severity = Severity::kWarning;

        finding.detail += "Test: ";
        finding.detail += path;
        finding.detail += "\n";

        finding.detail += "Owner: ";
        finding.detail += std::to_string(st.st_uid);
        finding.detail += "\n";

        if (st.st_uid == 0) {
            result.flags.root = true;
            is_abnormal = true;
            finding.detail += "Found ROOT PTY\n";
        }

        ssize_t len = getxattr(path, "security.selinux", attr_val, sizeof(attr_val) - 1);
        if (len > 0) {
            attr_val[len] = '\0';
            finding.detail += "SELinux: ";
            finding.detail += attr_val;
            finding.detail += "\n";

            if (strstr(attr_val, "ksu_file") != nullptr) {
                result.flags.root = true;
                result.flags.kernel_su = true;
                is_abnormal = true;
                finding.detail += "Found KernelSU file Domain\n";
            }
        }

        if (is_abnormal) {
            finding.value = "Abnormal Permission Detected\n";
            finding.severity = Severity::kDanger;
            result.findings.push_back(finding);
            result.hit_count++;
        }

        result.extra_text += finding.detail;
        result.extra_text += '\n';
    }

    ProbeResult run_devpts_permission_check() {
        ProbeResult result;
        result.extra_text = "";

        // scan current PTYs, we don't have search permission
        // So, let's manually test from 0 to 10
        char path_buf[32];
        for (int i = 0; i <= 10; ++i) {
            snprintf(path_buf, sizeof(path_buf), "/dev/pts/%d", i);
            check_and_fill_finding(path_buf, result);
        }

        // Create a new PTY, KernelSU with devpts hook will make it to u:object_r:ksu_file:s0
        int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
        if (master_fd != -1) {
            if (grantpt(master_fd) == 0 && unlockpt(master_fd) == 0) {
                char* pts_name = ptsname(master_fd);
                if (pts_name) {
                    check_and_fill_finding(pts_name, result);
                }
            }
            close(master_fd);
        }

        return result;
    }

} // namespace duckdetector::nativeroot