'''
Author: Nikolaos P.
Purpose: Generate filename as Chafer does
'''
import ctypes
import ctypes.wintypes

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ('wYear', ctypes.c_int16),
        ('wMonth', ctypes.c_int16),
        ('wDayOfWeek', ctypes.c_int16),
        ('wDay', ctypes.c_int16),
        ('wHour', ctypes.c_int16),
        ('wMinute', ctypes.c_int16),
        ('wSecond', ctypes.c_int16),
        ('wMilliseconds', ctypes.c_int16)]

class FILETIME(ctypes.Structure):
    _fields_ = (
        ('dwLowDateTime', ctypes.wintypes.DWORD),
        ('dwHighDateTime', ctypes.wintypes.DWORD),
    )

files_counter = 1 #Once a file has been created, this value is increased by one. If files_counter>=1000 then set it to 1 again.
SystemTime = SYSTEMTIME()
lpSystemTime = ctypes.pointer(SystemTime)

ctypes.windll.kernel32.GetSystemTime(lpSystemTime)
filetime = FILETIME()
lpFileTime = ctypes.pointer(filetime)


ctypes.windll.kernel32.SystemTimeToFileTime(lpSystemTime,lpFileTime)
print "filename: x{0:x}{1:d}{2:d}.tmp".format(filetime.dwLowDateTime,filetime.dwHighDateTime,files_counter)
files_counter +=1
