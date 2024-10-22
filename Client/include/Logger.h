#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <ctime>
#include <chrono>
#include <iomanip>

class Logger
{
private:
    std::string logFilePath;
    std::ofstream logFIle;
    std::mutex logMutex;

    
public:
    std::string getCurrentTIme();
    void log(const std::string& message);
    Logger(const std::string& filePath = "log.log");
    ~Logger();
};

