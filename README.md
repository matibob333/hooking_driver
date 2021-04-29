# hooking_driver

Goal of this project was driver which can count calls of system functions. Choosing of function is made by client app, where we can specify number of function which should be counted. It can also send order to write number of calls in debug console.

Project contains two elements:
* driver, which can obtain instructions from user application; hooks specific system function in that way, that it increment counter, than call original function
* client application which communicates with driver and sending him orders
