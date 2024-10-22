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

    std::string getCurrentTIme();
public:
    void log(const std::string& message);
    Logger(const std::string& filePath = "log.txt");
    ~Logger();
};

