/*

privwatch - a Linux security auditing tool designed to analyze running processes and 
uncover potential privilege escalation vectors.

Author: c0d3Ninja
Website: https://gotr00t0day.github.io

*/

#include <cctype>
#include <string>
#include <iostream>
#include <vector>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <set>
#include <limits.h>


#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define WHITE   "\033[37m"

static bool allDigits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

std::string resolvePath(const std::string& path) {
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved)) {
        return std::string(resolved);
    }
    return path;
}

std::vector<std::string> readCmdArgs(const std::string& pid) {
    std::ifstream file("/proc/" + pid + "/cmdline", std::ios::binary);
    std::vector<std::string> args;

    if (!file) return args;

    std::string arg;
    while (std::getline(file, arg, '\0')) {
        if (!arg.empty()) {
            args.push_back(arg);
        }
    }

    return args;
}

std::string readCmdline(const std::string& pid) {
    std::ifstream file("/proc/" + pid + "/cmdline", std::ios::binary);
    if (!file) return "";

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    for (char& c : content) {
        if (c == '\0') c = ' ';
    }

    return content;
}

std::string parseName(const std::string& line) {
    const auto pos = line.find(':');
    if (pos == std::string::npos) return "";

    std::string value = line.substr(pos + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    return value;
}

std::string readComm(const std::string& pid) {
    std::ifstream commFile("/proc/" + pid + "/comm");
    std::string line;

    if (commFile && std::getline(commFile, line)) {
        return line;
    }

    std::ifstream statFile("/proc/" + pid + "/status");
    while (std::getline(statFile, line)) {
        if (line.rfind("Name:", 0) == 0) {
            return parseName(line);
        }
    }

    return "";
}

std::string getUid(const std::string& pid) {
    std::ifstream file("/proc/" + pid + "/status");
    std::string line;

    while (std::getline(file, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            auto pos = line.find(':');
            std::string value = line.substr(pos + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            return value.substr(0, value.find_first_of(" \t"));
        }
    }
    return "";
}

std::string uidToUser(const std::string& uidStr) {
    if (uidStr.empty()) return "";

    uid_t uid = static_cast<uid_t>(std::stoi(uidStr));
    struct passwd* pw = getpwuid(uid);

    if (pw) return pw->pw_name;
    return uidStr;
}

bool isInterpreter(const std::string& exe) {
    return exe.find("python") != std::string::npos ||
           exe.find("bash")   != std::string::npos ||
           exe.find("sh")     != std::string::npos ||
           exe.find("perl")   != std::string::npos ||
           exe.find("php")    != std::string::npos ||
           exe.find("node")   != std::string::npos ||
           exe.find("java")   != std::string::npos ||
           exe.find("js")     != std::string::npos ||
           exe.find("jsx")    != std::string::npos ||
           exe.find("ts")     != std::string::npos ||
           exe.find("tsx")    != std::string::npos ||
           exe.find("go")     != std::string::npos ||
           exe.find("rust")   != std::string::npos ||
           exe.find("elixir") != std::string::npos ||
           exe.find("erlang") != std::string::npos ||
           exe.find("clojure") != std::string::npos ||
           exe.find("scala") != std::string::npos ||
           exe.find("kotlin") != std::string::npos ||
           exe.find("swift") != std::string::npos ||
           exe.find("dart") != std::string::npos ||
           exe.find("groovy") != std::string::npos ||
           exe.find("haskell") != std::string::npos ||
           exe.find("ocaml") != std::string::npos ||
           exe.find("elm") != std::string::npos ||
           exe.find("elm") != std::string::npos ||
           exe.find("ruby")   != std::string::npos;
}

std::vector<std::string> getExecutionTargets(const std::string& pid) {
    auto args = readCmdArgs(pid);
    std::set<std::string> targets;

    if (args.empty()) return {};

    const std::string& exe = args[0];

    if (isInterpreter(exe)) {
        if (args.size() > 1 && !args[1].empty() && args[1][0] == '/') {
            targets.insert(resolvePath(args[1]));
        }
    }

    if (!exe.empty() && exe[0] == '/') {
        targets.insert(resolvePath(exe));
    }

    for (const auto& arg : args) {
        if (!arg.empty() && arg[0] == '/' && arg.find('=') == std::string::npos) {
            targets.insert(resolvePath(arg));
        }
    }

    return std::vector<std::string>(targets.begin(), targets.end());
}

bool isDangerous(const std::string& path, uid_t procUid) {
    struct stat st;

    if (stat(path.c_str(), &st) != 0) return false;

    bool writable = (st.st_mode & S_IWOTH) || (st.st_mode & S_IWGRP);

    // Only flag if root process uses non-root writable file
    if (procUid == 0 && st.st_uid != 0 && writable) {
        return true;
    }

    return false;
}

std::string findVuln(const std::string& pid) {
    auto targets = getExecutionTargets(pid);
    std::string uidStr = getUid(pid);

    if (targets.empty() || uidStr.empty()) return "";

    uid_t uid = std::stoi(uidStr);

    for (const auto& target : targets) {
        if (isDangerous(target, uid)) {
            return RED "HIGH RISK: " + target + RESET;
        }
    }

    return "";
}

std::vector<std::string> getProcess() {
    std::vector<std::string> results;

    for (const auto& entry : std::filesystem::directory_iterator(
            "/proc", std::filesystem::directory_options::skip_permission_denied)) {

        std::string pid = entry.path().filename().string();

        if (!entry.is_directory() || !allDigits(pid))
            continue;

        std::string name = readComm(pid);
        std::string user = uidToUser(getUid(pid));
        std::string cmd  = readCmdline(pid);
        std::string vuln = findVuln(pid);

        if (!name.empty()) {
            results.emplace_back(
                BLUE + pid +
                MAGENTA + " -> " +
                YELLOW + name +
                MAGENTA + " -> " +
                GREEN + user +
                MAGENTA + " -> " +
                WHITE + cmd +
                MAGENTA + " -> " +
                vuln
            );
        }
    }

    return results;
}

int main() {
    for (const auto& p : getProcess()) {
        std::cout << p << '\n';
    }
    return 0;
}
