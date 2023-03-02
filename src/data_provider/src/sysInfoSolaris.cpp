/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <fstream>
#include <sys/utsname.h>
#include <unistd.h>
#include <dirent.h>
#include <procfs.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>

#include "osinfo/sysOsParsers.h"
#include "sharedDefs.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "timeHelper.h"
#include "filesystemHelper.h"
#include "packages/packageSolaris.h"
#include "packages/solarisWrapper.h"
#include "packages/packageFamilyDataAFactory.h"
#include "network/networkSolarisHelper.hpp"
#include "network/networkSolarisWrapper.hpp"
#include "network/networkFamilyDataAFactory.h"
#include "UtilsWrapperUnix.hpp"
#include "uniqueFD.hpp"

constexpr auto SUN_APPS_PATH {"/var/sadm/pkg/"};

const auto KBYTES_PER_PAGE { sysconf(_SC_PAGESIZE) / 1024 };

static void getOsInfoFromUname(nlohmann::json& info)
{
    bool result{false};
    std::string platform;
    const auto osPlatform{Utils::exec("uname")};

    constexpr auto SOLARIS_RELEASE_FILE{"/etc/release"};
    const auto spParser{FactorySysOsParser::create("solaris")};
    std::fstream file{SOLARIS_RELEASE_FILE, std::ios_base::in};
    result = spParser && file.is_open() && spParser->parseFile(file, info);

    if (!result)
    {
        info["os_name"] = "Unix";
        info["os_platform"] = "Unix";
        info["os_version"] = UNKNOWN_VALUE;
    }
}

// cache's data type and store
using MapCache = std::map<int, std::string>;
static MapCache groupNameCache;
static MapCache userNameCache;

static nlohmann::json getProcessInfo(std::string processName)
{
    // open the files needed to extract info
    std::ifstream ifInfo   { WM_SYS_PROC_DIR + processName + "/psinfo", std::ios::binary };
    std::ifstream ifStatus { WM_SYS_PROC_DIR + processName + "/status", std::ios::binary };
    std::ifstream ifCred   { WM_SYS_PROC_DIR + processName + "/cred", std::ios::binary };

    // a relevant info is not available, get out!
    if (!ifInfo.is_open())
    {
        return nlohmann::json();
    }

    // Group names cached
    auto getGroupName = [](const auto& key)
    {
        try
        {
            return groupNameCache.at(key);
        }
        catch(const std::out_of_range)
        {
            struct group *grent {getgrgid(key)};
            return (groupNameCache[key] = grent->gr_name);
        }
    };

    // User names cached
    auto getUserName = [](const auto& key)
    {
        try
        {
            return userNameCache.at(key);
        }
        catch(const std::out_of_range)
        {
            struct passwd *pwent {getpwuid(key)};
            return (userNameCache[key] = pwent->pw_name);
        }
    };

    // the relevant info is read
    psinfo_t info;
    ifInfo.read(reinterpret_cast<char*>(&info), sizeof info);

    // init the supplementary structs
    pstatus_t status;
    std::memset(&status, 0, sizeof status);

    prcred_t cred;
    std::memset(&cred, 0, sizeof cred);

    // try to read the supplementary data
    ifStatus.read(reinterpret_cast<char*>(&status), sizeof status);
    ifCred.read(reinterpret_cast<char*>(&cred), sizeof cred);

    nlohmann::json jsProcessInfo {};
    jsProcessInfo["pid"]        = std::to_string(info.pr_pid);
    jsProcessInfo["name"]       = std::string(info.pr_fname);
    jsProcessInfo["state"]      = std::string(1, info.pr_lwp.pr_sname);
    jsProcessInfo["ppid"]       = info.pr_ppid;
    jsProcessInfo["utime"]      = status.pr_utime.tv_sec;
    jsProcessInfo["stime"]      = status.pr_stime.tv_sec;

    // command and args splited
    const char* pargs { std::strpbrk(info.pr_psargs, " ") };
    jsProcessInfo["argvs"]      = pargs ? ++pargs : "";
    jsProcessInfo["cmd"]        = std::strtok(info.pr_psargs, " ");

    jsProcessInfo["euser"]      = getUserName(info.pr_euid);
    jsProcessInfo["ruser"]      = getUserName(info.pr_uid);
    jsProcessInfo["suser"]      = getUserName(cred.pr_suid);
    jsProcessInfo["egroup"]     = getGroupName(info.pr_egid);
    jsProcessInfo["rgroup"]     = getGroupName(cred.pr_rgid);
    jsProcessInfo["sgroup"]     = getGroupName(cred.pr_sgid);

    // I'm not a zombie
    if (info.pr_lwp.pr_sname != 'Z')
    {
        jsProcessInfo["priority"] = info.pr_lwp.pr_pri;
        if (info.pr_lwp.pr_oldpri != 0)
        {
            jsProcessInfo["nice"] = info.pr_lwp.pr_nice;
        }
    }

    jsProcessInfo["size"]       = info.pr_size / KBYTES_PER_PAGE;
    jsProcessInfo["vm_size"]    = info.pr_size;
    jsProcessInfo["resident"]   = info.pr_rssize / KBYTES_PER_PAGE;
    jsProcessInfo["share"];     // discarded information is not easily obtained
    jsProcessInfo["start_time"] = info.pr_lwp.pr_start.tv_sec;
    jsProcessInfo["pgrp"]       = info.pr_pgid;
    jsProcessInfo["session"]    = info.pr_sid;
    jsProcessInfo["nlwp"]       = info.pr_nlwp + info.pr_nzomb;
    jsProcessInfo["tgid"]       = info.pr_taskid;
    jsProcessInfo["tty"]        = info.pr_ttydev == PRNODEV ? 0 : info.pr_ttydev;
    jsProcessInfo["processor"]  = info.pr_lwp.pr_cpu;

    return jsProcessInfo;
}

std::string SysInfo::getSerialNumber() const
{
    return UNKNOWN_VALUE;
}
std::string SysInfo::getCpuName() const
{
    return UNKNOWN_VALUE;
}
int SysInfo::getCpuMHz() const
{
    return 0;
}
int SysInfo::getCpuCores() const
{
    return 0;
}
void SysInfo::getMemory(nlohmann::json& /*info*/) const
{

}

static void getPackagesFromPath(const std::string& pkgDirectory, std::function<void(nlohmann::json&)> callback)
{
    const auto packages { Utils::enumerateDir(pkgDirectory) };

    for (const auto& package : packages)
    {
        nlohmann::json jsPackage;
        const auto fullPath {  pkgDirectory + package };
        const auto pkgWrapper{ std::make_shared<SolarisWrapper>(fullPath) };

        FactoryPackageFamilyCreator<OSType::SOLARIS>::create(pkgWrapper)->buildPackageData(jsPackage);

        if (!jsPackage.at("name").get_ref<const std::string&>().empty())
        {
            // Only return valid content packages
            callback(jsPackage);
        }
    }
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json packages;

    getPackages([&packages](nlohmann::json & data)
    {
        packages.push_back(data);
    });

    return packages;
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};
    getOsInfoFromUname(ret);

    if (uname(&uts) >= 0)
    {
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
    }

    return ret;
}
nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};

    getProcessesInfo([&jsProcessesList](nlohmann::json & processInfo)
    {
        // Append the current json process object to the list of processes
        jsProcessesList.push_back(processInfo);
    });

    return jsProcessesList;
}
nlohmann::json SysInfo::getNetworks() const
{
    nlohmann::json networks;
    Utils::UniqueFD socketV4 ( UtilsWrapperUnix::createSocket(AF_INET, SOCK_DGRAM, 0) );
    Utils::UniqueFD socketV6 ( UtilsWrapperUnix::createSocket(AF_INET6, SOCK_DGRAM, 0) );
    const auto interfaceCount { NetworkSolarisHelper::getInterfacesCount(socketV4.get(), AF_UNSPEC) };

    if (interfaceCount > 0)
    {
        std::vector<lifreq> buffer(interfaceCount);
        lifconf lifc =
        {
            AF_UNSPEC,
            0,
            static_cast<int>(buffer.size() * sizeof(lifreq)),
            reinterpret_cast<caddr_t>(buffer.data())
        };

        NetworkSolarisHelper::getInterfacesConfig(socketV4.get(), lifc);

        std::map<std::string, std::vector<std::pair<lifreq*, uint64_t>>> interfaces;

        for (auto& item : buffer)
        {
            struct lifreq interfaceReq = {};
            std::memcpy(interfaceReq.lifr_name, item.lifr_name, sizeof(item.lifr_name));

            if (-1 != UtilsWrapperUnix::ioctl(AF_INET == item.lifr_addr.ss_family ? socketV4.get() : socketV6.get(),
                                              SIOCGLIFFLAGS,
                                              reinterpret_cast<char*>(&interfaceReq)))
            {
                if ((IFF_UP & interfaceReq.lifr_flags) && !(IFF_LOOPBACK & interfaceReq.lifr_flags))
                {
                    interfaces[item.lifr_name].push_back(std::make_pair(&item, interfaceReq.lifr_flags));
                }
            }
        }

        for (const auto& item : interfaces)
        {
            if (item.second.size())
            {
                const auto firstItem { item.second.front() };
                const auto firstItemFD { AF_INET == firstItem.first->lifr_addr.ss_family ? socketV4.get() : socketV6.get() };

                nlohmann::json network;

                for (const auto& itemr : item.second)
                {
                    if (AF_INET == itemr.first->lifr_addr.ss_family)
                    {
                        // IPv4 data
                        const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_INET, socketV4.get(), itemr) };
                        FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                    else if (AF_INET6 == itemr.first->lifr_addr.ss_family)
                    {
                        // IPv6 data
                        const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_INET6, socketV6.get(), itemr) };
                        FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                }

                const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_UNSPEC, firstItemFD, firstItem) };
                FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);

                networks["iface"].push_back(network);
            }
        }
    }

    return networks;
}
nlohmann::json SysInfo::getPorts() const
{
    return nlohmann::json();
}
void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> callback) const
{
    const auto procfiles { Utils::enumerateDir(WM_SYS_PROC_DIR) };

    for (const auto& procfile : procfiles)
    {
        if (procfile[0] == '.')
        {
            continue;
        }

        auto processInfo = getProcessInfo(procfile);
        callback(processInfo);
    }
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    const auto pkgDirectory { SUN_APPS_PATH };

    if (Utils::existsDir(pkgDirectory))
    {
        getPackagesFromPath(pkgDirectory, callback);
    }
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}
