#include <Windows.h>
#include <iostream>

using namespace std;

int main()
{
    HANDLE hDevice = CreateFileW(L"\\\\.\\MyDriver",          // drive to open
        GENERIC_READ | GENERIC_WRITE,                // no access to the drive
        0,                  // share mode
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        FILE_ATTRIBUTE_NORMAL,                // file attributes
        NULL);            // do not copy file attributes
    DWORD dziwne = 0;
    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        cout << "INVALID_HANDLE_VALUE" << endl;
        return 1;
    }
    cout << "otwarto sterownik" << endl;
    char zmienna[5] = "";
    
    do 
    {
        cin >> zmienna;
        if (zmienna[0] == 's')
        {
            WriteFile(hDevice, zmienna, strlen(zmienna), &dziwne, NULL);
        }
        else if (zmienna[0] >= '0' && zmienna[0] <= '9' && zmienna[1] >= '0' && zmienna[1] <= '9' && zmienna[2] >= '0' && zmienna[2] <= '9' && zmienna[3] >= '0' && zmienna[3] <= '9')
        {
            WriteFile(hDevice, zmienna, strlen(zmienna), &dziwne, NULL);
        }
        else if (zmienna[0] == 'c')
        {
            WriteFile(hDevice, zmienna, strlen(zmienna), &dziwne, NULL);
        }
        else if (zmienna[0] == 'q')
        {
            break;
        }
        else
        {
            cout << "zla komenda" << endl;
        }
    } while (true);
    CloseHandle(hDevice);
    return 0;
}