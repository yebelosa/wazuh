/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_SOLARIS_WRAPPER_H
#define _PROCESS_SOLARIS_WRAPPER_H

#include <map>
#include <dirent.h>
#include <procfs.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>

#include "iprocessWrapper.h"

const auto KBYTES_PER_PAGE{sysconf(_SC_PAGESIZE) / 1024};

// cache's data type and store
static std::map<int, std::string> groupNameCache, userNameCache;

class ProcessSolarisInterface final : public IProcessInterfaceWrapper
{
    psinfo_t m_info;
    pstatus_t m_status;
    prcred_t m_cred;

    // Group names cached
    static std::string &getGroupName(const auto &key)
    {
        try
        {
            return groupNameCache.at(key);
        }
        catch (const std::out_of_range)
        {
            struct group *grent{getgrgid(key)};
            return (groupNameCache[key] = grent->gr_name);
        }
    };

    // User names cached
    static std::string &getUserName(const auto &key)
    {
        try
        {
            return userNameCache.at(key);
        }
        catch (const std::out_of_range)
        {
            struct passwd *pwent{getpwuid(key)};
            return (userNameCache[key] = pwent->pw_name);
        }
    };

public:
    explicit ProcessSolarisInterface(std::ifstream &ifInfo, std::ifstream &ifStatus, std::ifstream &ifCred)
    {
        // a relevant info is not available, get out!
        if (!ifInfo.is_open())
        {
            throw std::runtime_error{"Error psinfo file not open!."};
        }

        ifInfo.read(reinterpret_cast<char *>(&m_info), sizeof m_info);

        // init the supplementary structs
        std::memset(&m_status, 0, sizeof m_status);
        std::memset(&m_cred, 0, sizeof m_cred);

        // try to read the supplementary data
        ifStatus.read(reinterpret_cast<char *>(&m_status), sizeof m_status);
        ifCred.read(reinterpret_cast<char *>(&m_cred), sizeof m_cred);
    }

    std::string pid() const override
    {
        return std::to_string(m_info.pr_pid);
    }

    std::string name() const override
    {
        return std::string(m_info.pr_fname);
    }

    std::string state() const override
    {
        return std::string(1, m_info.pr_lwp.pr_sname);
    }

    int ppid() const override
    {
        return m_info.pr_ppid;
    }

    unsigned long long utime() const override
    {
        return m_status.pr_utime.tv_sec;
    }

    unsigned long long stime() const override
    {
        return m_status.pr_stime.tv_sec;
    }

    std::string cmd() const override
    {
        char cmdCopy[PRARGSZ];
        std::strcpy(cmdCopy, m_info.pr_psargs);
        return std::strtok(cmdCopy, " ");
    }

    std::string argvs() const override
    {
        const char *pargs{std::strpbrk(m_info.pr_psargs, " ")};
        return pargs ? ++pargs : "";
    }

    std::string euser() const override
    {
        return getUserName(m_info.pr_euid);
    }

    std::string ruser() const override
    {
        return getUserName(m_info.pr_euid);
    }

    std::string suser() const override
    {
        return getUserName(m_info.pr_uid);
    }

    std::string egroup() const override
    {
        return getUserName(m_cred.pr_suid);
    }

    std::string rgroup() const override
    {
        return getGroupName(m_info.pr_egid);
    }

    std::string sgroup() const override
    {
        return getGroupName(m_cred.pr_rgid);
    }

    std::string fgroup() const override
    {
        return getGroupName(m_cred.pr_sgid);
    }

    long priority() const override
    {
        return (m_info.pr_lwp.pr_sname != 'Z') ? m_info.pr_lwp.pr_pri : -1L;
    }

    long nice() const override
    {
        return (m_info.pr_lwp.pr_sname != 'Z' && m_info.pr_lwp.pr_oldpri != 0) ? m_info.pr_lwp.pr_nice : -1L;
    }

    long size() const override
    {
        return m_info.pr_size / KBYTES_PER_PAGE;
    }

    unsigned long vm_size() const override
    {
        return m_info.pr_size;
    }

    long resident() const override
    {
        return m_info.pr_rssize / KBYTES_PER_PAGE;
    }

    long share() const override
    {
        return -1L; // discarded information is not easily obtained
    }

    unsigned long long start_time() const override
    {
        return m_info.pr_lwp.pr_start.tv_sec;
    }

    int pgrp() const override
    {
        return m_info.pr_pgid;
    }

    int session() const override
    {
        return m_info.pr_sid;
    }

    int nlwp() const override
    {
        return m_info.pr_nlwp + m_info.pr_nzomb;
    }

    int tgid() const override
    {
        return m_info.pr_taskid;
    }

    int tty() const override
    {
        return m_info.pr_ttydev == PRNODEV ? 0 : m_info.pr_ttydev;
    }

    int processor() const override
    {
        return m_info.pr_lwp.pr_cpu;
    }
};

#endif // _PROCESS_SOLARIS_WRAPPER_H
