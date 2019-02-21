#pragma once

#ifdef ENABLE_LOGGING
bool InitializeLogging();
void Log(const std::wstring& Text);
#else
#define Log(...)
#endif