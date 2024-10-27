#include "Logger.h"
#include <sys/stat.h>

Logger::Logger(const std::string& filePath) : logFilePath(filePath) {
    logFIle.open(logFilePath, std::ios::app);
    if(!logFIle.is_open()) {
        std::cerr << "Failed to open log File\n";
    }
}

std::string Logger::getCurrentTIme() {
        auto now = std::chrono::system_clock::now();
        std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
        std::tm* localTime = std::localtime(&nowTime);
        std::ostringstream oss;
        oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
        return oss.str();
}

Logger::~Logger() {
    if (logFIle.is_open()) {
        logFIle.close();
    }
}
void Logger::log(const std::string& message, const std::string& type) {
    std::lock_guard<std::mutex> lock(logMutex);

    std::string logMessage = "[" + type + "]: " +"[" + getCurrentTIme() + "]: " + message;
    
    logFIle << logMessage << std::endl;

    std::cout << logMessage << std::endl;
}

bool fileExists(const std::string& fileName) {
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}